mod config;
mod credential;
mod idcat;
mod token_source;

use crate::config::{Config, Repository};
use crate::credential::{
    Repo, is_github_https_request, read_credential_from_stdin, repo_from_credential,
};
use crate::idcat::fetch_installation_token;
use crate::token_source::read_token;
use clap::{Parser, ValueEnum};
use std::env;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() {
    if let Err(error) = run() {
        eprintln!("Fatal error, exiting: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    init_logging();

    let cli = Cli::try_parse()?;
    if cli.action != Action::Get {
        return Ok(());
    }

    let config = Config::load(cli.config_path)?;
    let credential = read_credential_from_stdin()?;
    if !is_github_https_request(&credential) {
        info!(
            protocol = ?credential.get("protocol"),
            host = ?credential.get("host"),
            "exiting without output because the request is not for https://github.com"
        );
        return Ok(());
    }

    let repo = match repo_from_credential(&credential) {
        Some(repo) => repo,
        None => {
            info!(
                path = ?credential.get("path"),
                "exiting without output because the GitHub HTTPS request did not include an owner/repo path"
            );
            return Ok(());
        }
    };

    if !answers_for(config.repository.as_ref(), &repo) {
        // Print nothing. Git treats an empty response as "this helper has no credential", moves on
        // to whatever else is configured, and never sees a value for this repository.
        info!(
            requested_owner = %repo.owner,
            requested_repo = %repo.name,
            "exiting without output because this helper is configured for a different repository"
        );
        return Ok(());
    }

    info!("obtaining bearer token");
    let oidc_token = read_token(&config.token_source)?;
    info!("bearer token obtained");
    let installation_token = fetch_installation_token(&config, &repo, &oidc_token)?;

    println!("username=x-access-token");
    println!("password={installation_token}");
    println!();

    Ok(())
}

/// Whether this helper should produce a credential for `requested`.
///
/// A configured repository is a hard boundary: the helper prints nothing for anything else, so
/// Git receives no credential from it and falls through to whatever else is configured. GitHub
/// owner and repository names are case-insensitive, so the comparison is too — otherwise a clone
/// URL differing only in case would silently get no credential.
fn answers_for(configured: Option<&Repository>, requested: &Repo) -> bool {
    match configured {
        None => true,
        Some(configured) => {
            configured.owner.eq_ignore_ascii_case(&requested.owner)
                && configured.name.eq_ignore_ascii_case(&requested.name)
        }
    }
}

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long = "config", short = 'c')]
    config_path: Option<PathBuf>,

    #[arg(value_enum)]
    action: Action,
}

#[derive(Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Action {
    Get,
    Store,
    Erase,
}

fn init_logging() {
    tracing_subscriber::registry()
        .with(EnvFilter::new(env::var("RUST_LOG").unwrap_or_else(|_| {
            format!("{}=info", env!("CARGO_CRATE_NAME"))
        })))
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_writer(std::io::stderr),
        )
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(owner: &str, name: &str) -> Repo {
        Repo {
            owner: owner.to_owned(),
            name: name.to_owned(),
        }
    }

    fn configured(owner: &str, name: &str) -> Repository {
        Repository {
            owner: owner.to_owned(),
            name: name.to_owned(),
        }
    }

    #[test]
    fn answers_for_the_configured_repository() {
        assert!(answers_for(
            Some(&configured("myorg", "pilot")),
            &repo("myorg", "pilot")
        ));
    }

    #[test]
    fn does_not_answer_for_another_repository_in_the_same_org() {
        assert!(!answers_for(
            Some(&configured("myorg", "pilot")),
            &repo("myorg", "other")
        ));
    }

    #[test]
    fn does_not_answer_for_the_same_repository_name_under_another_owner() {
        assert!(!answers_for(
            Some(&configured("myorg", "pilot")),
            &repo("otherorg", "pilot")
        ));
    }

    #[test]
    fn does_not_answer_for_a_repository_whose_name_merely_starts_the_same() {
        assert!(!answers_for(
            Some(&configured("myorg", "pilot")),
            &repo("myorg", "pilot-internal")
        ));
    }

    #[test]
    fn matches_case_insensitively_as_github_does() {
        assert!(answers_for(
            Some(&configured("MyOrg", "Pilot")),
            &repo("myorg", "pilot")
        ));
    }

    #[test]
    fn answers_for_anything_when_no_repository_is_configured() {
        assert!(answers_for(None, &repo("myorg", "anything")));
    }
}
