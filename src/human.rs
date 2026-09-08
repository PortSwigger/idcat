// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

//! Validation of Teleport-issued JWTs presented by a *person*, as opposed to the workload tokens
//! handled by [`crate::service::TokenValidator`] (which delegates to `authzoo`).
//!
//! This exists as an idcat-local validator rather than a change to `authzoo` because the human
//! path needs four things `authzoo` 0.1.4 does not offer, and which cannot be expressed through
//! its `RoleConfig` (`#[serde(deny_unknown_fields)]`):
//!
//! * **Array-valued role claims.** Teleport puts a user's roles in a JSON array. `authzoo`'s
//!   `ValidatedClaims::claim_value` ends in `.and_then(Value::as_str)`, so an array claim reads
//!   back as absent and can never match. A *scalar* claim of the same name must not be accepted
//!   as a substitute, or a token minted by a different issuer shape could impersonate a role.
//! * **An explicitly configured JWKS URL.** `authzoo` only reaches a JWKS through
//!   `GET {issuer}/.well-known/openid-configuration`. Teleport publishes a JWKS directly, and the
//!   pilot must not depend on OpenID discovery for this issuer.
//! * **The validated claims, not just role names.** `authzoo::TokenValidator::validate` returns
//!   `Vec<String>` of role names, discarding `sub`. A person-level issuance record needs the
//!   subject.
//! * **One parse per request.** `authzoo` validates once per configured role, and idcat's
//!   `validate_role_with_claims` builds a fresh validator per candidate policy, so an invalid
//!   token costs N parses and N key lookups. Here the issuer is chosen from configuration first
//!   and the token is parsed exactly once.

use anyhow::Context;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::debug;

/// The path a Teleport JWKS is published under. An operator-supplied `jwks-url` must end in this,
/// so a typo cannot silently point key discovery at an arbitrary endpoint.
pub const TELEPORT_JWKS_PATH: &str = "/.well-known/jwks.json";

/// How long a fetched JWKS is reused before it is fetched again.
const JWKS_CACHE_TTL: Duration = Duration::from_secs(15 * 60);

/// The shortest interval between two JWKS fetches provoked by an unrecognised `kid`. Without this
/// floor, a stream of tokens carrying junk `kid` values would become a fetch amplifier against the
/// Teleport proxy.
const JWKS_REFETCH_FLOOR: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum HumanTokenError {
    #[error("token header could not be decoded")]
    MalformedHeader,
    #[error("token algorithm {0:?} is not allowed for this issuer")]
    AlgorithmNotAllowed(Algorithm),
    #[error("no validation key matched the token's key id")]
    UnknownKeyId,
    #[error("token signature, issuer, audience, expiry or not-before check failed")]
    TokenRejected,
    #[error("claim '{claim}' is not a JSON array of strings")]
    RoleClaimNotAnArray { claim: String },
    #[error("required role '{role}' is not present in claim '{claim}'")]
    RoleNotHeld { claim: String, role: String },
    #[error("claim '{claim}' did not match the configured requirement")]
    ClaimMismatch { claim: String },
    #[error("validation keys could not be retrieved")]
    KeysUnavailable,
}

/// The claims of a token that has passed every check, kept whole rather than reduced to a role
/// name so that an issuance record can name the person.
#[derive(Clone, Debug)]
pub struct HumanClaims {
    subject: String,
    claims: BTreeMap<String, Value>,
}

impl HumanClaims {
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// A scalar claim, for joining an issuance record to the Teleport access request or session
    /// that authorised it. Returns `None` for an absent or non-string claim.
    pub fn claim_str(&self, claim: &str) -> Option<&str> {
        self.claims.get(claim).and_then(Value::as_str)
    }
}

#[derive(Debug, Deserialize)]
struct RawClaims {
    sub: String,
    #[serde(flatten)]
    claims: BTreeMap<String, Value>,
}

/// Where validation keys come from.
#[derive(Clone)]
enum JwksSource {
    /// Fetched from a configured URL and cached.
    Http {
        url: String,
        client: reqwest::Client,
    },
    /// Supplied directly, so a test never reaches the network.
    #[cfg(test)]
    Static(Arc<JwkSet>),
}

struct CachedJwks {
    jwks: Arc<JwkSet>,
    fetched_at: Instant,
}

#[derive(Clone)]
pub struct HumanTokenValidator {
    issuer: String,
    audience: String,
    algorithms: Vec<Algorithm>,
    source: JwksSource,
    cache: Arc<RwLock<Option<CachedJwks>>>,
}

impl HumanTokenValidator {
    pub fn from_http(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_url: impl Into<String>,
        algorithms: Vec<Algorithm>,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(2))
            .build()
            .context("failed to build the Teleport JWKS client")?;
        Ok(Self::new(
            issuer,
            audience,
            algorithms,
            JwksSource::Http {
                url: jwks_url.into(),
                client,
            },
        ))
    }

    #[cfg(test)]
    pub fn from_static_jwks(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks: JwkSet,
        algorithms: Vec<Algorithm>,
    ) -> Self {
        Self::new(
            issuer,
            audience,
            algorithms,
            JwksSource::Static(Arc::new(jwks)),
        )
    }

    fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        algorithms: Vec<Algorithm>,
        source: JwksSource,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms,
            source,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Validates `token` once: signature, exact issuer, exact audience, expiry and not-before,
    /// then the configured role membership and any additional scalar claim requirements.
    pub async fn validate(
        &self,
        token: &str,
        roles_claim: &str,
        required_role: &str,
        required_claims: &BTreeMap<String, authzoo::ClaimRequirement>,
    ) -> Result<HumanClaims, HumanTokenError> {
        let header = decode_header(token).map_err(|_| HumanTokenError::MalformedHeader)?;
        if !self.algorithms.contains(&header.alg) {
            return Err(HumanTokenError::AlgorithmNotAllowed(header.alg));
        }

        let key = self.decoding_key(header.kid.as_deref(), header.alg).await?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        // The pilot's approval window is one hour; a clock-skew grace period long enough to matter
        // would eat into it, and both ends are NTP-disciplined.
        validation.leeway = 0;

        let decoded = decode::<RawClaims>(token, &key, &validation).map_err(|error| {
            debug!(error = %error, "human token rejected during signature or registered-claim validation");
            HumanTokenError::TokenRejected
        })?;

        let claims = decoded.claims;
        let roles = role_members(&claims.claims, roles_claim)?;
        // Exact string equality against each element: a role that merely *contains* the required
        // name, or a scalar claim that happens to spell it, must not grant access.
        if !roles.iter().any(|held| held == required_role) {
            return Err(HumanTokenError::RoleNotHeld {
                claim: roles_claim.to_string(),
                role: required_role.to_string(),
            });
        }

        for (claim, requirement) in required_claims {
            let value = claims.claims.get(claim).and_then(Value::as_str);
            if !requirement.matches(value) {
                return Err(HumanTokenError::ClaimMismatch {
                    claim: claim.clone(),
                });
            }
        }

        Ok(HumanClaims {
            subject: claims.sub,
            claims: claims.claims,
        })
    }

    async fn decoding_key(
        &self,
        kid: Option<&str>,
        algorithm: Algorithm,
    ) -> Result<DecodingKey, HumanTokenError> {
        let jwks = self.jwks(false).await?;
        if let Some(key) = select_key(&jwks, kid, algorithm) {
            return Ok(key);
        }
        // An unrecognised key id most often means the issuer has rotated, so try once more with a
        // forced fetch before rejecting.
        let jwks = self.jwks(true).await?;
        select_key(&jwks, kid, algorithm).ok_or(HumanTokenError::UnknownKeyId)
    }

    async fn jwks(&self, force: bool) -> Result<Arc<JwkSet>, HumanTokenError> {
        let (url, client) = match &self.source {
            #[cfg(test)]
            JwksSource::Static(jwks) => return Ok(Arc::clone(jwks)),
            JwksSource::Http { url, client } => (url, client),
        };

        {
            let cached = self.cache.read().await;
            if let Some(cached) = cached.as_ref() {
                let age = cached.fetched_at.elapsed();
                let usable = if force {
                    age < JWKS_REFETCH_FLOOR
                } else {
                    age < JWKS_CACHE_TTL
                };
                if usable {
                    return Ok(Arc::clone(&cached.jwks));
                }
            }
        }

        let mut cache = self.cache.write().await;
        // Another task may have refreshed while this one waited for the write lock.
        if let Some(cached) = cache.as_ref() {
            let age = cached.fetched_at.elapsed();
            let usable = if force {
                age < JWKS_REFETCH_FLOOR
            } else {
                age < JWKS_CACHE_TTL
            };
            if usable {
                return Ok(Arc::clone(&cached.jwks));
            }
        }

        debug!(jwks_url = %url, "fetching Teleport JWKS");
        let fetched: JwkSet = client
            .get(url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| {
                debug!(jwks_url = %url, error = %error, "Teleport JWKS request failed");
                HumanTokenError::KeysUnavailable
            })?
            .json()
            .await
            .map_err(|error| {
                debug!(jwks_url = %url, error = %error, "Teleport JWKS could not be parsed");
                HumanTokenError::KeysUnavailable
            })?;

        let fetched = Arc::new(fetched);
        *cache = Some(CachedJwks {
            jwks: Arc::clone(&fetched),
            fetched_at: Instant::now(),
        });
        Ok(fetched)
    }
}

/// Reads `roles_claim` as a JSON array of strings. A scalar claim of the same name is an error
/// rather than a single-element array: accepting it would let a token shaped like a different
/// issuer's satisfy a Teleport role requirement.
fn role_members(
    claims: &BTreeMap<String, Value>,
    roles_claim: &str,
) -> Result<Vec<String>, HumanTokenError> {
    let value = claims
        .get(roles_claim)
        .ok_or_else(|| HumanTokenError::RoleClaimNotAnArray {
            claim: roles_claim.to_string(),
        })?;
    let Value::Array(entries) = value else {
        return Err(HumanTokenError::RoleClaimNotAnArray {
            claim: roles_claim.to_string(),
        });
    };
    entries
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| HumanTokenError::RoleClaimNotAnArray {
                    claim: roles_claim.to_string(),
                })
        })
        .collect()
}

fn select_key(jwks: &JwkSet, kid: Option<&str>, algorithm: Algorithm) -> Option<DecodingKey> {
    let jwk = match kid {
        Some(kid) => jwks.find(kid)?,
        // Teleport stamps a `kid`, but a JWKS holding exactly one key is unambiguous without one.
        None => match jwks.keys.as_slice() {
            [only] => only,
            _ => return None,
        },
    };
    if let Some(key_algorithm) = jwk.common.key_algorithm
        && key_algorithm.to_string() != format!("{algorithm:?}")
    {
        return None;
    }
    DecodingKey::from_jwk(jwk).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkeys::{TeleportClaims, other_keys, test_keys};
    use serde_json::json;

    const ISSUER: &str = "https://teleport.example.invalid";
    // The audience is the Teleport *application uri*, which is deliberately not the human-facing
    // proxy hostname; conflating the two is the mistake this constant exists to make visible.
    const AUDIENCE: &str = "https://idcat.teleport.example.invalid:443";
    const ROLES_CLAIM: &str = "roles";
    const ROLE: &str = "github-app-token-pilot-repo";

    fn validator() -> HumanTokenValidator {
        HumanTokenValidator::from_static_jwks(
            ISSUER,
            AUDIENCE,
            test_keys().jwks.clone(),
            vec![Algorithm::RS256],
        )
    }

    async fn validate(token: &str) -> Result<HumanClaims, HumanTokenError> {
        validator()
            .validate(token, ROLES_CLAIM, ROLE, &BTreeMap::new())
            .await
    }

    fn claims(roles: serde_json::Value) -> TeleportClaims {
        TeleportClaims::new("alex.mason@example.invalid", ISSUER, AUDIENCE, roles)
    }

    #[tokio::test]
    async fn accepts_a_token_whose_roles_array_contains_the_required_role() {
        let token = test_keys().sign(&claims(json!(["some-other-role", ROLE])));

        let validated = validate(&token).await.unwrap();

        assert_eq!(validated.subject(), "alex.mason@example.invalid");
    }

    #[tokio::test]
    async fn returns_the_subject_so_an_issuance_record_can_name_the_person() {
        let mut raw = claims(json!([ROLE]));
        raw.sub = "someone.else@example.invalid".to_string();
        let token = test_keys().sign(&raw);

        assert_eq!(
            validate(&token).await.unwrap().subject(),
            "someone.else@example.invalid",
            "a successful validation must not be reduced to role names"
        );
    }

    #[test]
    fn role_members_reads_a_json_array_of_strings() {
        let claims = BTreeMap::from([(ROLES_CLAIM.to_string(), json!(["some-other-role", ROLE]))]);

        assert_eq!(
            role_members(&claims, ROLES_CLAIM).unwrap(),
            ["some-other-role", ROLE]
        );
    }

    #[tokio::test]
    async fn rejects_a_scalar_claim_that_merely_looks_like_the_roles_array() {
        let token = test_keys().sign(&claims(json!(ROLE)));

        assert_eq!(
            validate(&token).await.unwrap_err(),
            HumanTokenError::RoleClaimNotAnArray {
                claim: ROLES_CLAIM.to_string()
            }
        );
    }

    #[tokio::test]
    async fn rejects_a_role_that_is_only_a_substring_of_a_held_role() {
        let token = test_keys().sign(&claims(json!([format!("{ROLE}-readonly")])));

        assert_eq!(
            validate(&token).await.unwrap_err(),
            HumanTokenError::RoleNotHeld {
                claim: ROLES_CLAIM.to_string(),
                role: ROLE.to_string()
            }
        );
    }

    #[tokio::test]
    async fn rejects_a_role_the_required_name_merely_contains() {
        let token = test_keys().sign(&claims(json!(["github-app-token"])));

        assert!(matches!(
            validate(&token).await.unwrap_err(),
            HumanTokenError::RoleNotHeld { .. }
        ));
    }

    #[tokio::test]
    async fn rejects_a_roles_array_holding_a_non_string_entry() {
        let token = test_keys().sign(&claims(json!([ROLE, 7])));

        assert!(matches!(
            validate(&token).await.unwrap_err(),
            HumanTokenError::RoleClaimNotAnArray { .. }
        ));
    }

    #[tokio::test]
    async fn rejects_a_missing_roles_claim() {
        #[derive(serde::Serialize)]
        struct NoRoles {
            sub: &'static str,
            iss: &'static str,
            aud: &'static str,
            exp: u64,
        }
        let token = test_keys().sign(&NoRoles {
            sub: "alex.mason@example.invalid",
            iss: ISSUER,
            aud: AUDIENCE,
            exp: crate::testkeys::now() + 3600,
        });

        assert!(matches!(
            validate(&token).await.unwrap_err(),
            HumanTokenError::RoleClaimNotAnArray { .. }
        ));
    }

    #[tokio::test]
    async fn rejects_a_wrong_audience() {
        let mut raw = claims(json!([ROLE]));
        raw.aud = "https://idcat.teleport.example.invalid".to_string();
        let token = test_keys().sign(&raw);

        assert_eq!(
            validate(&token).await.unwrap_err(),
            HumanTokenError::TokenRejected,
            "the audience must match the Teleport application uri exactly, not a prefix of it"
        );
    }

    #[tokio::test]
    async fn rejects_the_human_route_hostname_used_as_an_audience() {
        let mut raw = claims(json!([ROLE]));
        raw.aud = "https://idcat.example.invalid".to_string();
        let token = test_keys().sign(&raw);

        assert_eq!(
            validate(&token).await.unwrap_err(),
            HumanTokenError::TokenRejected
        );
    }

    #[tokio::test]
    async fn rejects_a_wrong_issuer() {
        let mut raw = claims(json!([ROLE]));
        raw.iss = "https://teleport.other.invalid".to_string();
        let token = test_keys().sign(&raw);

        assert_eq!(
            validate(&token).await.unwrap_err(),
            HumanTokenError::TokenRejected
        );
    }

    #[tokio::test]
    async fn rejects_a_signature_from_another_key() {
        let token = other_keys().sign(&claims(json!([ROLE])));

        assert_eq!(
            validate(&token).await.unwrap_err(),
            HumanTokenError::TokenRejected
        );
    }

    #[tokio::test]
    async fn rejects_an_expired_token_without_leeway() {
        let mut raw = claims(json!([ROLE]));
        raw.exp = crate::testkeys::now() - 1;
        let token = test_keys().sign(&raw);

        assert_eq!(
            validate(&token).await.unwrap_err(),
            HumanTokenError::TokenRejected
        );
    }

    #[tokio::test]
    async fn rejects_a_token_that_is_not_yet_valid() {
        let mut raw = claims(json!([ROLE]));
        raw.nbf = crate::testkeys::now() + 600;
        let token = test_keys().sign(&raw);

        assert_eq!(
            validate(&token).await.unwrap_err(),
            HumanTokenError::TokenRejected
        );
    }

    #[tokio::test]
    async fn rejects_an_unsigned_token() {
        let mut raw = claims(json!([ROLE]));
        raw.exp = crate::testkeys::now() + 3600;
        let unsigned = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::HS256),
            &raw,
            &jsonwebtoken::EncodingKey::from_secret(b"not-the-issuer-key"),
        )
        .unwrap();

        assert_eq!(
            validate(&unsigned).await.unwrap_err(),
            HumanTokenError::AlgorithmNotAllowed(Algorithm::HS256),
            "an HMAC token must be refused on algorithm, never checked against an RSA public key"
        );
    }

    #[tokio::test]
    async fn rejects_a_malformed_token() {
        assert_eq!(
            validate("not-a-jwt").await.unwrap_err(),
            HumanTokenError::MalformedHeader
        );
    }

    #[tokio::test]
    async fn rejects_a_token_signed_by_a_key_absent_from_the_jwks() {
        let validator = HumanTokenValidator::from_static_jwks(
            ISSUER,
            AUDIENCE,
            other_keys().jwks.clone(),
            vec![Algorithm::RS256],
        );
        let token = test_keys().sign(&claims(json!([ROLE])));

        // Both key sets stamp the same kid, so selection succeeds and the signature check is what
        // rejects this. The distinct-kid case is covered by `rejects_an_unknown_key_id`.
        assert_eq!(
            validator
                .validate(&token, ROLES_CLAIM, ROLE, &BTreeMap::new())
                .await
                .unwrap_err(),
            HumanTokenError::TokenRejected
        );
    }

    #[tokio::test]
    async fn rejects_an_unknown_key_id() {
        let validator = HumanTokenValidator::from_static_jwks(
            ISSUER,
            AUDIENCE,
            crate::testkeys::TestKeyPair::generate("a-different-kid").jwks,
            vec![Algorithm::RS256],
        );
        let token = test_keys().sign(&claims(json!([ROLE])));

        assert_eq!(
            validator
                .validate(&token, ROLES_CLAIM, ROLE, &BTreeMap::new())
                .await
                .unwrap_err(),
            HumanTokenError::UnknownKeyId
        );
    }

    #[tokio::test]
    async fn enforces_additional_scalar_claim_requirements() {
        let mut raw = claims(json!([ROLE]));
        raw.traits = Some(json!("contractor"));
        let token = test_keys().sign(&raw);
        let required = BTreeMap::from([(
            "traits".to_string(),
            authzoo::ClaimRequirement::equals("employee"),
        )]);

        assert_eq!(
            validator()
                .validate(&token, ROLES_CLAIM, ROLE, &required)
                .await
                .unwrap_err(),
            HumanTokenError::ClaimMismatch {
                claim: "traits".to_string()
            }
        );
    }
}
