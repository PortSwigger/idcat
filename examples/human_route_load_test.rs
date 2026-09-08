// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

//! Bounded invalid-token load test for the human installation-token route.
//!
//! # Why this exists
//!
//! `authzoo` validates a token once per configured role, and the OpenID discovery request it makes
//! when a role has no `validation-key` is not cached — only the resulting JWKS key is. An invalid
//! token can therefore cost several blocking outbound requests on a worker thread. The human route
//! avoids that (it selects one issuer from configuration and parses once, against a cached JWKS),
//! but the *existing* workload consumers still run through `authzoo`, and they share a runtime with
//! the new route. This measures whether load on the new route degrades them.
//!
//! # This will not run without owner-supplied values
//!
//! The request ceiling, permitted latency change, duration and environment are not guessable, and
//! guessing them would either make the test meaningless or turn it into an outage. Every one of
//! them is a required argument, and the target is refused if it looks like production.
//!
//! ```text
//! cargo run --example human_route_load_test -- \
//!   --environment <name supplied by the owner> \
//!   --human-url https://<non-production idcat>/human/installation-token/<app>/<owner>/<repo> \
//!   --workload-url https://<non-production idcat>/installation-token/<app>/<owner>/<repo> \
//!   --workload-token-file <path to a non-production workload token> \
//!   --requests-per-second <ceiling supplied by the owner> \
//!   --duration-seconds <supplied by the owner> \
//!   --max-latency-increase-ms <supplied by the owner> \
//!   --i-am-the-named-owner
//! ```
//!
//! Exits non-zero if the measured latency increase exceeds the supplied threshold, which is the
//! signal to complete the wider validator repair before the pilot goes live.

use clap::Parser;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Environment names that must never be a load-test target, however the flags are set.
const FORBIDDEN_ENVIRONMENT_MARKERS: [&str; 4] = ["prod", "live", "production", "public"];

#[derive(Debug, Parser)]
#[command(
    about = "Bounded invalid-token load test for the idcat human token route",
    long_about = None
)]
struct Cli {
    /// The non-production environment named by the owner who authorised this test.
    #[arg(long)]
    environment: String,

    /// The human installation-token route to load with invalid tokens.
    #[arg(long)]
    human_url: String,

    /// An existing workload installation-token route, whose latency is the thing being protected.
    #[arg(long)]
    workload_url: String,

    /// File holding a non-production workload token. Passed as a path, never on the command line,
    /// so the token cannot appear in process arguments or shell history.
    #[arg(long)]
    workload_token_file: std::path::PathBuf,

    /// The request ceiling supplied by the owner. There is no default.
    #[arg(long)]
    requests_per_second: u32,

    /// How long to sustain the load, supplied by the owner. There is no default.
    #[arg(long)]
    duration_seconds: u64,

    /// The largest acceptable increase in workload p95 latency, supplied by the owner.
    #[arg(long)]
    max_latency_increase_ms: u64,

    /// Affirms that the caller is the named owner permitted to run this.
    #[arg(long)]
    i_am_the_named_owner: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    guard(&cli)?;

    let workload_token = std::fs::read_to_string(&cli.workload_token_file)?
        .trim()
        .to_string();
    if workload_token.is_empty() {
        anyhow::bail!("workload token file is empty");
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("measuring workload latency with no additional load");
    let baseline = measure_workload(&client, &cli.workload_url, &workload_token, 20).await;
    report("baseline", &baseline);

    println!(
        "applying {} invalid requests/second to the human route for {}s",
        cli.requests_per_second, cli.duration_seconds
    );
    let sent = Arc::new(AtomicU64::new(0));
    let load = tokio::spawn(apply_load(
        client.clone(),
        cli.human_url.clone(),
        cli.requests_per_second,
        Duration::from_secs(cli.duration_seconds),
        Arc::clone(&sent),
    ));

    let under_load = measure_workload(&client, &cli.workload_url, &workload_token, 20).await;
    load.await??;
    report("under load", &under_load);
    println!("invalid requests sent: {}", sent.load(Ordering::Relaxed));

    let increase = under_load.p95.saturating_sub(baseline.p95);
    println!(
        "workload p95 increased by {}ms (permitted: {}ms)",
        increase.as_millis(),
        cli.max_latency_increase_ms
    );
    if increase > Duration::from_millis(cli.max_latency_increase_ms) {
        anyhow::bail!(
            "workload p95 latency increase exceeded the permitted change; complete the wider \
             validator repair before the pilot goes live"
        );
    }
    println!("within the permitted latency change");
    Ok(())
}

/// Refuses to run unless the owner has supplied every bound and the target is non-production.
fn guard(cli: &Cli) -> anyhow::Result<()> {
    if !cli.i_am_the_named_owner {
        anyhow::bail!(
            "this test may only be run by the named owner; pass --i-am-the-named-owner to affirm that"
        );
    }
    if cli.requests_per_second == 0 || cli.duration_seconds == 0 {
        anyhow::bail!("requests-per-second and duration-seconds must be greater than zero");
    }
    let environment = cli.environment.to_ascii_lowercase();
    for marker in FORBIDDEN_ENVIRONMENT_MARKERS {
        if environment.contains(marker) {
            anyhow::bail!(
                "environment '{}' looks like production; this test runs only in the named \
                 non-production environment",
                cli.environment
            );
        }
        for url in [&cli.human_url, &cli.workload_url] {
            if url.to_ascii_lowercase().contains(marker) {
                anyhow::bail!(
                    "target '{url}' looks like production; this test runs only in the named \
                     non-production environment"
                );
            }
        }
    }
    Ok(())
}

struct Latencies {
    p50: Duration,
    p95: Duration,
    p99: Duration,
    errors: usize,
}

fn report(label: &str, latencies: &Latencies) {
    println!(
        "{label}: p50={}ms p95={}ms p99={}ms errors={}",
        latencies.p50.as_millis(),
        latencies.p95.as_millis(),
        latencies.p99.as_millis(),
        latencies.errors
    );
}

async fn measure_workload(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    samples: usize,
) -> Latencies {
    let mut observed = Vec::with_capacity(samples);
    let mut errors = 0;
    for _ in 0..samples {
        let started = Instant::now();
        match client.post(url).bearer_auth(token).send().await {
            Ok(response) if response.status().is_success() => observed.push(started.elapsed()),
            Ok(_) | Err(_) => errors += 1,
        }
    }
    observed.sort_unstable();
    Latencies {
        p50: percentile(&observed, 50),
        p95: percentile(&observed, 95),
        p99: percentile(&observed, 99),
        errors,
    }
}

fn percentile(sorted: &[Duration], percentile: usize) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let index = (sorted.len() * percentile / 100).min(sorted.len() - 1);
    sorted[index]
}

/// Sends structurally valid but cryptographically worthless tokens. Nothing here is a credential.
async fn apply_load(
    client: reqwest::Client,
    url: String,
    requests_per_second: u32,
    duration: Duration,
    sent: Arc<AtomicU64>,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + duration;
    let interval = Duration::from_secs_f64(1.0 / f64::from(requests_per_second));
    let token = synthetic_invalid_token();
    while Instant::now() < deadline {
        let client = client.clone();
        let url = url.clone();
        let token = token.clone();
        let sent = Arc::clone(&sent);
        tokio::spawn(async move {
            let _ = client.post(&url).bearer_auth(&token).send().await;
            sent.fetch_add(1, Ordering::Relaxed);
        });
        tokio::time::sleep(interval).await;
    }
    Ok(())
}

/// A well-formed JWT whose signature is meaningless, so it exercises the full validation path and
/// is rejected. It carries no real claims and is not a credential.
fn synthetic_invalid_token() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT","kid":"load-test"}"#);
    let claims = URL_SAFE_NO_PAD
        .encode(br#"{"sub":"load-test","iss":"load-test","aud":"load-test","exp":9999999999}"#);
    let signature = URL_SAFE_NO_PAD.encode([0u8; 256]);
    format!("{header}.{claims}.{signature}")
}
