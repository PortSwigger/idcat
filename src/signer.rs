// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use anyhow::Context;
use rsa::{
    RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs1v15::SigningKey, pkcs8::DecodePrivateKey,
    sha2::Sha256,
};
use signature::{SignatureEncoding, Signer as _};
use std::future::Future;
use std::pin::Pin;

pub trait Signer: Send + Sync {
    /// Signs the JWT signing input with RSASSA-PKCS1-v1_5 using SHA-256.
    ///
    /// Implementations should return the raw signature bytes. `build_github_app_jwt`
    /// handles base64url encoding those bytes into the final JWT.
    fn sign<'a>(
        &'a self,
        message: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a>>;
}

#[derive(Clone)]
pub struct LocalSigner {
    private_key: RsaPrivateKey,
}

impl LocalSigner {
    pub fn from_rsa_pem(private_key_pem: &str) -> anyhow::Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_key_pem))
            .context("failed to parse GitHub App RSA private key")?;
        Ok(Self { private_key })
    }
}

impl std::fmt::Debug for LocalSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalSigner")
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl Signer for LocalSigner {
    fn sign<'a>(
        &'a self,
        message: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
            Ok(signing_key.sign(message).to_vec())
        })
    }
}
