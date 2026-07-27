// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::error::AppError;
use axum::http::HeaderMap;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const SIGNATURE_HEADER: &str = "x-hub-signature-256";

/// Validate a GitHub webhook delivery against the shared secret stored in
/// `secret_file`, following the scheme described at
/// <https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>.
///
/// The secret is read from the file on every delivery so it can be rotated
/// without restarting idcat. Surrounding whitespace (including a trailing
/// newline, which most editors add) is trimmed from the file contents.
pub async fn validate_delivery(
    secret_file: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), AppError> {
    let secret = tokio::fs::read_to_string(secret_file)
        .await
        .map_err(|error| {
            AppError::Internal(format!(
                "failed to read webhook validation secret from '{secret_file}': {error}"
            ))
        })?;
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(AppError::Internal(format!(
            "webhook validation secret file '{secret_file}' is empty"
        )));
    }

    let signature = headers
        .get(SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized(format!("missing {SIGNATURE_HEADER} header")))?;

    if verify_signature(secret.as_bytes(), body, signature) {
        Ok(())
    } else {
        Err(AppError::Unauthorized(
            "webhook signature validation failed".to_string(),
        ))
    }
}

/// Returns true when `signature_header` is a valid `sha256=<hex>` HMAC of
/// `body` keyed with `secret`. The comparison is constant time.
fn verify_signature(secret: &[u8], body: &[u8], signature_header: &str) -> bool {
    let Some(hex_signature) = signature_header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_signature) else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::verify_signature;

    // Example from GitHub's "validating webhook deliveries" documentation.
    const SECRET: &[u8] = b"It's a Secret to Everybody";
    const BODY: &[u8] = b"Hello, World!";
    const SIGNATURE: &str =
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    #[test]
    fn accepts_valid_signature() {
        assert!(verify_signature(SECRET, BODY, SIGNATURE));
    }

    #[test]
    fn rejects_signature_computed_with_wrong_secret() {
        assert!(!verify_signature(b"wrong secret", BODY, SIGNATURE));
    }

    #[test]
    fn rejects_signature_for_tampered_body() {
        assert!(!verify_signature(SECRET, b"Goodbye, World!", SIGNATURE));
    }

    #[test]
    fn rejects_signature_without_sha256_prefix() {
        let bare = SIGNATURE.strip_prefix("sha256=").unwrap();
        assert!(!verify_signature(SECRET, BODY, bare));
    }

    #[test]
    fn rejects_non_hex_signature() {
        assert!(!verify_signature(SECRET, BODY, "sha256=not-hex"));
    }
}
