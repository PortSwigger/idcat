// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

//! Locally generated RSA keys and synthetic signed JWTs for tests.
//!
//! Nothing here is a credential: the key pair is generated in-process, lives only for the lifetime
//! of the test binary, and is never written to disk. Tests must never be given a real Teleport
//! token, GitHub token or App private key.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, rand_core::OsRng};
use serde::Serialize;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const TEST_KID: &str = "idcat-test-key";

/// A generated key pair, together with the JWKS a validator would fetch for it.
pub struct TestKeyPair {
    pub private_key_pem: String,
    pub jwks: JwkSet,
}

/// Generating a 2048-bit key is the slowest thing in the test suite, so do it once per binary.
fn shared() -> &'static Arc<TestKeyPair> {
    static SHARED: OnceLock<Arc<TestKeyPair>> = OnceLock::new();
    SHARED.get_or_init(|| Arc::new(TestKeyPair::generate(TEST_KID)))
}

pub fn test_keys() -> Arc<TestKeyPair> {
    Arc::clone(shared())
}

/// A second, unrelated key pair, for proving that a token signed by the wrong issuer is rejected.
pub fn other_keys() -> Arc<TestKeyPair> {
    static OTHER: OnceLock<Arc<TestKeyPair>> = OnceLock::new();
    Arc::clone(OTHER.get_or_init(|| Arc::new(TestKeyPair::generate(TEST_KID))))
}

impl TestKeyPair {
    pub fn generate(kid: &str) -> Self {
        let private_key =
            RsaPrivateKey::new(&mut OsRng, 2048).expect("test RSA key generation must succeed");
        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("test RSA key must encode as PKCS#8 PEM")
            .to_string();

        let modulus = URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());
        let exponent = URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());
        let jwks = serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": modulus,
                "e": exponent,
            }]
        }))
        .expect("generated JWKS must parse");

        Self {
            private_key_pem,
            jwks,
        }
    }

    pub fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes())
            .expect("generated PEM must parse as an RSA signing key")
    }

    /// Signs `claims` as an RS256 JWT carrying [`TEST_KID`].
    pub fn sign(&self, claims: &impl Serialize) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        jsonwebtoken::encode(&header, claims, &self.encoding_key())
            .expect("synthetic test token must encode")
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after the unix epoch")
        .as_secs()
}

/// The claim shape of a Teleport application JWT: `roles` is an array, and `sub` names the person.
#[derive(Debug, Serialize)]
pub struct TeleportClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub nbf: u64,
    pub roles: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traits: Option<serde_json::Value>,
}

impl TeleportClaims {
    pub fn new(sub: &str, issuer: &str, audience: &str, roles: serde_json::Value) -> Self {
        let now = now();
        Self {
            sub: sub.to_string(),
            iss: issuer.to_string(),
            aud: audience.to_string(),
            exp: now + 3600,
            nbf: now - 5,
            roles,
            traits: None,
        }
    }
}
