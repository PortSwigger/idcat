// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

//! The person-level issuance record for the human token path.
//!
//! GitHub's own App record shows that *the App* minted a token; it cannot show which person asked
//! for it. These events are the only place that link is made, so they are emitted at `info` — the
//! level a production deployment actually keeps — for denials as well as grants.
//!
//! Nothing here may take a bearer token, an Authorization header, an App private key or a
//! credential-helper payload. The only token-derived value recorded is a truncated digest, which
//! lets an operator correlate two records without being able to reconstruct the token.

use crate::service::HumanIdentity;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tracing::info;

/// The number of hex characters of the token digest recorded. 16 hex characters (64 bits) is
/// ample to correlate records, and useless for recovering the token.
const FINGERPRINT_LENGTH: usize = 16;

/// A non-secret, stable identifier for a token. Correlates an idcat issuance record with another
/// record of the same token without disclosing it.
pub fn token_fingerprint(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)[..FINGERPRINT_LENGTH].to_string()
}

fn permissions_label(permissions: &BTreeMap<String, String>) -> String {
    permissions
        .iter()
        .map(|(permission, value)| format!("{permission}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Records that a person was issued a token for exactly one repository.
pub fn record_issuance(
    identity: &HumanIdentity,
    github_app: &str,
    repository: &str,
    permissions: &BTreeMap<String, String>,
    expires_at: &str,
    token: &str,
) {
    info!(
        event = "human_installation_token",
        decision = "allow",
        subject = %identity.subject,
        teleport_request = identity.request_id.as_deref().unwrap_or("unknown"),
        human_role = %identity.human_role,
        github_app = %github_app,
        repository = %repository,
        permissions = %permissions_label(permissions),
        expires_at = %expires_at,
        token_fingerprint = %token_fingerprint(token),
        "issued a GitHub App installation token to a person"
    );
}

/// Records that a person's request was refused. `subject` is absent when the token itself failed
/// validation, since nothing in an unvalidated token may be treated as an identity.
pub fn record_denial(subject: Option<&str>, github_app: &str, repository: &str, reason: &str) {
    info!(
        event = "human_installation_token",
        decision = "deny",
        subject = subject.unwrap_or("unauthenticated"),
        github_app = %github_app,
        repository = %repository,
        reason = %reason,
        "refused a GitHub App installation token request from a person"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    /// Captures what the tracing layer actually writes, so the assertions below are about the
    /// emitted log line rather than about the arguments we believe we passed.
    #[derive(Clone, Default)]
    struct CapturedLog(Arc<Mutex<Vec<u8>>>);

    impl CapturedLog {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Runs `emit` with a subscriber at the level a production deployment keeps, and returns what
    /// was logged.
    fn capture_at_info(emit: impl FnOnce()) -> String {
        use tracing_subscriber::layer::SubscriberExt;

        let captured = CapturedLog::default();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(captured.clone())
                    .with_ansi(false),
            );
        tracing::subscriber::with_default(subscriber, emit);
        captured.contents()
    }

    fn identity() -> HumanIdentity {
        HumanIdentity {
            subject: "alex.mason@example.invalid".to_string(),
            request_id: Some("req-1".to_string()),
            human_role: "pilot-repo-reader".to_string(),
        }
    }

    const SYNTHETIC_TOKEN: &str = "ghs_synthetic_token_value_for_tests";

    #[test]
    fn an_issuance_record_is_emitted_at_info() {
        let logged = capture_at_info(|| {
            record_issuance(
                &identity(),
                "source-reader",
                "myorg/pilot",
                &BTreeMap::from([("contents".to_string(), "read".to_string())]),
                "2099-01-01T00:00:00Z",
                SYNTHETIC_TOKEN,
            );
        });

        assert!(!logged.is_empty(), "the record must survive an INFO filter");
    }

    #[test]
    fn an_issuance_record_carries_everything_needed_to_join_it_to_the_approval() {
        let logged = capture_at_info(|| {
            record_issuance(
                &identity(),
                "source-reader",
                "myorg/pilot",
                &BTreeMap::from([("contents".to_string(), "read".to_string())]),
                "2099-01-01T00:00:00Z",
                SYNTHETIC_TOKEN,
            );
        });

        for expected in [
            "alex.mason@example.invalid",
            "req-1",
            "pilot-repo-reader",
            "source-reader",
            "myorg/pilot",
            "contents=read",
            "2099-01-01T00:00:00Z",
            &token_fingerprint(SYNTHETIC_TOKEN),
            "allow",
        ] {
            assert!(
                logged.contains(expected),
                "issuance record is missing '{expected}': {logged}"
            );
        }
    }

    #[test]
    fn an_issuance_record_never_contains_the_token() {
        let logged = capture_at_info(|| {
            record_issuance(
                &identity(),
                "source-reader",
                "myorg/pilot",
                &BTreeMap::from([("contents".to_string(), "read".to_string())]),
                "2099-01-01T00:00:00Z",
                SYNTHETIC_TOKEN,
            );
        });

        assert!(
            !logged.contains(SYNTHETIC_TOKEN),
            "the bearer token must never reach a log: {logged}"
        );
        assert!(
            !logged.contains("ghs_"),
            "no GitHub token prefix may appear in a log: {logged}"
        );
    }

    #[test]
    fn a_denial_is_emitted_at_info_without_inventing_an_identity() {
        let logged = capture_at_info(|| {
            record_denial(
                None,
                "source-reader",
                "myorg/other",
                "no human-policy authorizes",
            );
        });

        assert!(logged.contains("deny"), "{logged}");
        assert!(logged.contains("myorg/other"), "{logged}");
        assert!(
            logged.contains("unauthenticated"),
            "an unvalidated token must not be reported as an identity: {logged}"
        );
    }

    #[test]
    fn a_denial_after_validation_names_the_person() {
        let logged = capture_at_info(|| {
            record_denial(
                Some("alex.mason@example.invalid"),
                "source-reader",
                "myorg/pilot",
                "GitHub rejected the request",
            );
        });

        assert!(logged.contains("alex.mason@example.invalid"), "{logged}");
        assert!(logged.contains("deny"), "{logged}");
    }

    #[test]
    fn fingerprint_is_stable_and_short() {
        assert_eq!(
            token_fingerprint("ghs_example"),
            token_fingerprint("ghs_example")
        );
        assert_eq!(token_fingerprint("ghs_example").len(), FINGERPRINT_LENGTH);
    }

    #[test]
    fn fingerprint_differs_between_tokens() {
        assert_ne!(token_fingerprint("ghs_one"), token_fingerprint("ghs_two"));
    }

    #[test]
    fn fingerprint_does_not_contain_the_token() {
        let token = "ghs_averyrecognisablesecretvalue";

        assert!(
            !token_fingerprint(token).contains("averyrecognisable"),
            "a fingerprint that echoed the token would defeat its purpose"
        );
    }

    #[test]
    fn permissions_label_is_ordered_and_complete() {
        let permissions = BTreeMap::from([
            ("metadata".to_string(), "read".to_string()),
            ("contents".to_string(), "read".to_string()),
        ]);

        assert_eq!(
            permissions_label(&permissions),
            "contents=read,metadata=read"
        );
    }
}
