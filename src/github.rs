// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::config::GithubAppConfig;
use crate::jwt::build_github_app_jwt;
use crate::signer::Signer;
use anyhow::Context;
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, USER_AGENT,
};
use reqwest::{Client, Method, Response};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::debug;

const GITHUB_API_VERSION_HEADER: &str = "X-GitHub-Api-Version";
const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_API_URL: &str = "https://api.github.com";
const INSTALLATION_TOKEN_CACHE_TTL: Duration = Duration::from_secs(50 * 60);

#[derive(Clone)]
pub struct GithubClient {
    client: Client,
    api_url: String,
    cache: Arc<Mutex<GithubCache>>,
}

#[derive(Default)]
struct GithubCache {
    installation_ids: BTreeMap<String, u64>,
    installation_tokens: BTreeMap<InstallationTokenCacheKey, CachedInstallationToken>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct InstallationTokenCacheKey {
    github_app: String,
    repositories: Option<Vec<String>>,
    permissions: BTreeMap<String, String>,
}

#[derive(Clone)]
struct CachedInstallationToken {
    token: InstallationTokenResponse,
    refresh_after: Instant,
}

#[derive(Debug, Serialize)]
struct CreateInstallationTokenRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    repositories: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<BTreeMap<String, String>>,
}

fn build_create_installation_token_request(
    repositories: Option<&[String]>,
    permissions: &BTreeMap<String, String>,
) -> CreateInstallationTokenRequest {
    let repositories = repositories.map(|repositories| {
        repositories
            .iter()
            .map(|repo| {
                repo.split_once('/')
                    .map(|(_, name)| name)
                    .unwrap_or(repo)
                    .to_string()
            })
            .collect()
    });
    CreateInstallationTokenRequest {
        repositories,
        permissions: (!permissions.is_empty()).then(|| permissions.clone()),
    }
}

#[derive(Debug, Deserialize)]
struct RepositoryInstallationResponse {
    id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallationTokenResponse {
    pub token: String,
    pub expires_at: String,
    #[serde(default)]
    pub permissions: BTreeMap<String, String>,
    #[serde(default)]
    pub repository_selection: Option<String>,
}

impl GithubClient {
    pub fn new() -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("idcat"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            GITHUB_API_VERSION_HEADER,
            HeaderValue::from_static(GITHUB_API_VERSION),
        );
        let client = Client::builder()
            .default_headers(headers)
            .build()
            .context("failed to build GitHub API client")?;
        Ok(Self {
            client,
            api_url: GITHUB_API_URL.to_string(),
            cache: Arc::new(Mutex::new(GithubCache::default())),
        })
    }

    pub async fn create_installation_token(
        &self,
        github_app: &GithubAppConfig,
        signer: &dyn Signer,
        repo: &str,
        scope: crate::service::TokenScope,
    ) -> anyhow::Result<InstallationTokenResponse> {
        use crate::service::RepoScope;
        let repositories = match scope.repositories {
            RepoScope::All => None,
            RepoScope::OnlyRequested => Some(vec![repo.to_string()]),
        };
        self.create_installation_token_for_repositories(
            github_app,
            signer,
            repo,
            repositories,
            scope.permissions,
        )
        .await
    }

    pub async fn create_installation_token_for_multiple_repositories(
        &self,
        github_app: &GithubAppConfig,
        signer: &dyn Signer,
        mut repositories: Vec<String>,
        permissions: BTreeMap<String, String>,
    ) -> anyhow::Result<InstallationTokenResponse> {
        repositories.sort();
        let repo = repositories
            .first()
            .context("at least one repository is required")?
            .clone();
        self.create_installation_token_for_repositories(
            github_app,
            signer,
            &repo,
            Some(repositories),
            permissions,
        )
        .await
    }

    async fn create_installation_token_for_repositories(
        &self,
        github_app: &GithubAppConfig,
        signer: &dyn Signer,
        repo: &str,
        repositories: Option<Vec<String>>,
        permissions: BTreeMap<String, String>,
    ) -> anyhow::Result<InstallationTokenResponse> {
        let token_cache_key = InstallationTokenCacheKey {
            github_app: github_app.name.clone(),
            repositories,
            permissions,
        };
        if let Some(token) = self.cached_installation_token(&token_cache_key).await {
            debug!(
                github_app = %github_app.name,
                repo = %repo,
                repositories = ?token_cache_key.repositories,
                "using cached GitHub installation access token"
            );
            return Ok(token);
        }
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            repositories = ?token_cache_key.repositories,
            "cached GitHub installation access token not found or expired"
        );
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            app_id = github_app.app_id,
            "building GitHub App JWT"
        );
        let jwt = build_github_app_jwt(github_app.app_id, signer).await?;
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            "resolving GitHub App installation id"
        );
        let installation_id = self
            .cached_repository_installation_id(&jwt, &github_app.name, repo)
            .await?;
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            installation_id,
            "resolved GitHub App installation id"
        );
        let request = build_create_installation_token_request(
            token_cache_key.repositories.as_deref(),
            &token_cache_key.permissions,
        );
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            installation_id,
            "sending GitHub installation access token request"
        );
        let response = self
            .client
            .post(format!(
                "{}/app/installations/{}/access_tokens",
                self.api_url, installation_id
            ))
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .json(&request)
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed to request installation access token for '{}' with github_app '{}'",
                    repo, github_app.name
                )
            })?;

        let token: InstallationTokenResponse = response
            .error_for_status()
            .with_context(|| {
                format!(
                    "GitHub installation access token request for '{}' with github_app '{}' returned an error status",
                    repo, github_app.name
                )
            })?
            .json()
            .await
            .with_context(|| {
                format!(
                    "failed to parse GitHub installation access token response for '{}' with github_app '{}'",
                    repo, github_app.name
                )
            })?;
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            installation_id,
            expires_at = %token.expires_at,
            repository_selection = ?token.repository_selection,
            "parsed GitHub installation access token response"
        );
        self.cache_installation_token(token_cache_key, token.clone())
            .await;
        Ok(token)
    }

    pub async fn proxy_request(
        &self,
        method: Method,
        github_path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: Vec<u8>,
        installation_token: &str,
    ) -> anyhow::Result<Response> {
        let url = self.proxy_url(github_path, query);
        debug!(method = %method, url = %url, "forwarding proxied GitHub API request");
        self.client
            .request(method, url)
            .headers(proxy_headers(headers, installation_token)?)
            .body(body)
            .send()
            .await
            .context("failed to forward proxied GitHub API request")
    }

    async fn repository_installation_id(&self, jwt: &str, repo: &str) -> anyhow::Result<u64> {
        let (owner, repo_name) = repo
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("repo '{repo}' must use owner/repo format"))?;
        debug!(repo = %repo, owner = %owner, repo_name = %repo_name, "looking up repository installation");
        let installation: RepositoryInstallationResponse = self
            .client
            .get(format!(
                "{}/repos/{}/{}/installation",
                self.api_url, owner, repo_name
            ))
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .send()
            .await
            .with_context(|| format!("failed to resolve GitHub App installation for '{repo}'"))?
            .error_for_status()
            .with_context(|| {
                format!("GitHub App installation lookup for '{repo}' returned an error status")
            })?
            .json()
            .await
            .with_context(|| {
                format!("failed to parse GitHub App installation lookup response for '{repo}'")
            })?;
        debug!(repo = %repo, installation_id = installation.id, "repository installation lookup parsed");
        Ok(installation.id)
    }

    async fn cached_repository_installation_id(
        &self,
        jwt: &str,
        github_app_name: &str,
        repo: &str,
    ) -> anyhow::Result<u64> {
        let cache_key = format!("{github_app_name}/{repo}");
        if let Some(installation_id) = self
            .cache
            .lock()
            .await
            .installation_ids
            .get(&cache_key)
            .copied()
        {
            debug!(
                github_app = %github_app_name,
                repo = %repo,
                installation_id,
                "using cached GitHub App installation id"
            );
            return Ok(installation_id);
        }
        debug!(
            github_app = %github_app_name,
            repo = %repo,
            "cached GitHub App installation id not found"
        );
        let installation_id = self.repository_installation_id(jwt, repo).await?;
        self.cache
            .lock()
            .await
            .installation_ids
            .insert(cache_key, installation_id);
        debug!(
            github_app = %github_app_name,
            repo = %repo,
            installation_id,
            "cached GitHub App installation id"
        );
        Ok(installation_id)
    }

    async fn cached_installation_token(
        &self,
        key: &InstallationTokenCacheKey,
    ) -> Option<InstallationTokenResponse> {
        let now = Instant::now();
        self.cache
            .lock()
            .await
            .installation_tokens
            .get(key)
            .filter(|cached| cached.refresh_after > now)
            .map(|cached| cached.token.clone())
    }

    async fn cache_installation_token(
        &self,
        key: InstallationTokenCacheKey,
        token: InstallationTokenResponse,
    ) {
        let refresh_after = Instant::now() + INSTALLATION_TOKEN_CACHE_TTL;
        self.cache.lock().await.installation_tokens.insert(
            key,
            CachedInstallationToken {
                token,
                refresh_after,
            },
        );
    }

    fn proxy_url(&self, github_path: &str, query: Option<&str>) -> String {
        let path = github_path.trim_start_matches('/');
        match query {
            Some(query) if !query.is_empty() => format!("{}/{path}?{query}", self.api_url),
            _ => format!("{}/{path}", self.api_url),
        }
    }
}

fn proxy_headers(headers: &HeaderMap, installation_token: &str) -> anyhow::Result<HeaderMap> {
    let mut proxied = HeaderMap::new();
    for (name, value) in headers {
        if should_forward_header(name) {
            proxied.insert(name.clone(), value.clone());
        }
    }
    proxied.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {installation_token}"))
            .context("failed to build proxied GitHub Authorization header")?,
    );
    Ok(proxied)
}

fn should_forward_header(name: &HeaderName) -> bool {
    !matches!(
        name,
        &AUTHORIZATION
            | &HOST
            | &CONTENT_LENGTH
            | &reqwest::header::CONNECTION
            | &reqwest::header::PROXY_AUTHENTICATE
            | &reqwest::header::PROXY_AUTHORIZATION
            | &reqwest::header::TE
            | &reqwest::header::TRAILER
            | &reqwest::header::TRANSFER_ENCODING
            | &reqwest::header::UPGRADE
    )
}

#[cfg(test)]
mod tests {
    use super::{GithubClient, build_create_installation_token_request};
    use crate::config::GithubAppConfig;
    use crate::service::{RepoScope, TokenScope};
    use crate::signer::Signer;
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StubSigner;

    impl Signer for StubSigner {
        fn sign<'a>(
            &'a self,
            _message: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a>> {
            Box::pin(async { Ok(vec![1, 2, 3]) })
        }
    }

    /// Stub GitHub API that resolves a fixed installation id and mints a
    /// uniquely-numbered token on each POST, returning the running mint count
    /// so a cache hit (which skips the POST) is observable from the test.
    async fn spawn_stub_github_api() -> (String, Arc<AtomicUsize>) {
        use axum::Json;
        use axum::routing::{get, post};

        let mint_count = Arc::new(AtomicUsize::new(0));
        let mint_count_for_handler = mint_count.clone();
        let app = axum::Router::new()
            .route(
                "/repos/{owner}/{repo}/installation",
                get(|| async { Json(serde_json::json!({ "id": 123 })) }),
            )
            .route(
                "/app/installations/{id}/access_tokens",
                post(move || {
                    let mint_count = mint_count_for_handler.clone();
                    async move {
                        let n = mint_count.fetch_add(1, Ordering::SeqCst) + 1;
                        Json(serde_json::json!({
                            "token": format!("ghs_token_{n}"),
                            "expires_at": "2099-01-01T00:00:00Z",
                        }))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), mint_count)
    }

    fn test_github_app() -> GithubAppConfig {
        GithubAppConfig {
            name: "default".to_string(),
            app_id: 42,
            secret_key: "private-key.pem".to_string(),
            webhook_target: None,
            webhook_validation_secret_file: None,
            allowed_roles: Vec::new(),
        }
    }

    fn broad_scope() -> TokenScope {
        TokenScope {
            repositories: RepoScope::All,
            permissions: BTreeMap::new(),
        }
    }

    fn narrow_scope(permissions: &[(&str, &str)]) -> TokenScope {
        TokenScope {
            repositories: RepoScope::OnlyRequested,
            permissions: permissions
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[tokio::test]
    async fn narrow_caller_is_not_served_a_cached_broad_token() {
        let (api_url, mint_count) = spawn_stub_github_api().await;
        let mut client = GithubClient::new().unwrap();
        client.api_url = api_url;
        let github_app = test_github_app();

        // A broad-scoped caller mints and caches a token for the repo first.
        let broad = client
            .create_installation_token(&github_app, &StubSigner, "myorg/alfa", broad_scope())
            .await
            .unwrap();
        // A caller authorized only for the requested repo then asks for the same
        // repo. It must get its own freshly-minted, repo-scoped token — not the
        // cached broad token covering the whole installation.
        let narrow = client
            .create_installation_token(&github_app, &StubSigner, "myorg/alfa", narrow_scope(&[]))
            .await
            .unwrap();

        assert_ne!(
            broad.token, narrow.token,
            "narrow caller received the cached broad-scoped token"
        );
        assert_eq!(
            mint_count.load(Ordering::SeqCst),
            2,
            "each scope must mint its own token rather than share a cache entry"
        );
    }

    #[tokio::test]
    async fn caller_is_not_served_a_cached_token_with_different_permissions() {
        let (api_url, mint_count) = spawn_stub_github_api().await;
        let mut client = GithubClient::new().unwrap();
        client.api_url = api_url;
        let github_app = test_github_app();

        // A read-only caller mints and caches a token for the repo.
        let read = client
            .create_installation_token(
                &github_app,
                &StubSigner,
                "myorg/alfa",
                narrow_scope(&[("contents", "read")]),
            )
            .await
            .unwrap();
        // A caller authorized for write to the same repo must get its own
        // freshly-minted token — never the cached read-only one.
        let write = client
            .create_installation_token(
                &github_app,
                &StubSigner,
                "myorg/alfa",
                narrow_scope(&[("contents", "write")]),
            )
            .await
            .unwrap();

        assert_ne!(
            read.token, write.token,
            "write caller received the cached read-only token"
        );
        assert_eq!(
            mint_count.load(Ordering::SeqCst),
            2,
            "each permission set must mint its own token rather than share a cache entry"
        );
    }

    #[test]
    fn build_create_installation_token_request_broad_omits_repositories() {
        let request = build_create_installation_token_request(None, &BTreeMap::new());
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json, serde_json::json!({}));
    }

    #[test]
    fn build_create_installation_token_request_narrow_sets_repository_by_name() {
        let repositories = vec!["myorg/alfa".to_string()];
        let request =
            build_create_installation_token_request(Some(&repositories), &BTreeMap::new());
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json, serde_json::json!({ "repositories": ["alfa"] }));
    }

    #[test]
    fn build_create_installation_token_request_narrow_includes_permissions() {
        let repositories = vec!["myorg/alfa".to_string(), "myorg/bravo".to_string()];
        let permissions = BTreeMap::from([("contents".to_string(), "read".to_string())]);
        let request = build_create_installation_token_request(Some(&repositories), &permissions);
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "repositories": ["alfa", "bravo"],
                "permissions": { "contents": "read" }
            })
        );
    }

    #[tokio::test]
    async fn repository_order_does_not_change_multiple_repository_cache_key() {
        let (api_url, mint_count) = spawn_stub_github_api().await;
        let mut client = GithubClient::new().unwrap();
        client.api_url = api_url;
        let github_app = test_github_app();
        let permissions = BTreeMap::from([("contents".to_string(), "read".to_string())]);

        client
            .create_installation_token_for_multiple_repositories(
                &github_app,
                &StubSigner,
                vec!["myorg/alfa".to_string(), "myorg/bravo".to_string()],
                permissions.clone(),
            )
            .await
            .unwrap();
        client
            .create_installation_token_for_multiple_repositories(
                &github_app,
                &StubSigner,
                vec!["myorg/bravo".to_string(), "myorg/alfa".to_string()],
                permissions,
            )
            .await
            .unwrap();

        assert_eq!(mint_count.load(Ordering::SeqCst), 1);
    }
}
