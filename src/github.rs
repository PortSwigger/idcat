// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::config::GithubAppConfig;
use crate::jwt::build_github_app_jwt;
use crate::signer::Signer;
use anyhow::Context;
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, USER_AGENT,
};
use reqwest::{Client, Method, Response, StatusCode};
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

/// What a token request is aimed at. A repository resolves the installation through the repository
/// and can be scoped down to it; an owner resolves the installation through the account itself and
/// has no repository to scope to, so it always yields an installation-wide token.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InstallationTarget {
    /// A repository in `owner/name` form.
    Repository(String),
    /// An account (organization or user) that has the GitHub App installed.
    Owner(String),
}

impl InstallationTarget {
    /// A cache key that cannot collide across variants, so an owner named `alfa` never shares an
    /// entry with a repository whose path happens to render the same way.
    fn cache_key(&self) -> String {
        match self {
            Self::Repository(repo) => format!("repo:{repo}"),
            Self::Owner(owner) => format!("owner:{owner}"),
        }
    }
}

impl std::fmt::Display for InstallationTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repository(repo) => write!(formatter, "repository '{repo}'"),
            Self::Owner(owner) => write!(formatter, "owner '{owner}'"),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct InstallationTokenCacheKey {
    github_app: String,
    target: InstallationTarget,
    scope: crate::service::TokenScope,
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
    scope: &crate::service::TokenScope,
    target: &InstallationTarget,
) -> anyhow::Result<CreateInstallationTokenRequest> {
    use crate::service::RepoScope;
    let repositories = match (scope.repositories, target) {
        (RepoScope::All, _) => None,
        (RepoScope::OnlyRequested, InstallationTarget::Repository(repo)) => {
            let repo_name = repo.split_once('/').map(|(_, name)| name).unwrap_or(repo);
            Some(vec![repo_name.to_string()])
        }
        // An owner request names no repository to scope to. Falling back to an installation-wide
        // token here would hand out a broader token than the caller was authorized for, so refuse.
        (RepoScope::OnlyRequested, InstallationTarget::Owner(owner)) => {
            anyhow::bail!(
                "cannot mint a repository-scoped token for owner '{owner}': no repository was requested"
            );
        }
    };
    Ok(CreateInstallationTokenRequest {
        repositories,
        permissions: (!scope.permissions.is_empty()).then(|| scope.permissions.clone()),
    })
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
        target: &InstallationTarget,
        scope: crate::service::TokenScope,
    ) -> anyhow::Result<InstallationTokenResponse> {
        let token_cache_key = InstallationTokenCacheKey {
            github_app: github_app.name.clone(),
            target: target.clone(),
            scope,
        };
        if let Some(token) = self.cached_installation_token(&token_cache_key).await {
            debug!(
                github_app = %github_app.name,
                target = %target,
                "using cached GitHub installation access token"
            );
            return Ok(token);
        }
        debug!(
            github_app = %github_app.name,
            target = %target,
            "cached GitHub installation access token not found or expired"
        );
        debug!(
            github_app = %github_app.name,
            target = %target,
            app_id = github_app.app_id,
            "building GitHub App JWT"
        );
        let jwt = build_github_app_jwt(github_app.app_id, signer).await?;
        debug!(
            github_app = %github_app.name,
            target = %target,
            "resolving GitHub App installation id"
        );
        let installation_id = self
            .cached_installation_id(&jwt, &github_app.name, target)
            .await?;
        debug!(
            github_app = %github_app.name,
            target = %target,
            installation_id,
            "resolved GitHub App installation id"
        );
        let request = build_create_installation_token_request(&token_cache_key.scope, target)?;
        debug!(
            github_app = %github_app.name,
            target = %target,
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
                    "failed to request installation access token for {} with github_app '{}'",
                    target, github_app.name
                )
            })?;

        let token: InstallationTokenResponse = response
            .error_for_status()
            .with_context(|| {
                format!(
                    "GitHub installation access token request for {} with github_app '{}' returned an error status",
                    target, github_app.name
                )
            })?
            .json()
            .await
            .with_context(|| {
                format!(
                    "failed to parse GitHub installation access token response for {} with github_app '{}'",
                    target, github_app.name
                )
            })?;
        debug!(
            github_app = %github_app.name,
            target = %target,
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

    async fn installation_id(&self, jwt: &str, target: &InstallationTarget) -> anyhow::Result<u64> {
        match target {
            InstallationTarget::Repository(repo) => {
                self.repository_installation_id(jwt, repo).await
            }
            InstallationTarget::Owner(owner) => self.owner_installation_id(jwt, owner).await,
        }
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

    /// Resolves the installation for an account. `owner` may name either an organization or a user,
    /// and GitHub serves those from different endpoints, so try the organization first and fall back
    /// to the user endpoint when the account is not an organization.
    async fn owner_installation_id(&self, jwt: &str, owner: &str) -> anyhow::Result<u64> {
        debug!(owner = %owner, "looking up organization installation");
        match self
            .installation_id_from_path(jwt, &format!("orgs/{owner}/installation"))
            .await?
        {
            Some(installation_id) => {
                debug!(owner = %owner, installation_id, "organization installation lookup parsed");
                Ok(installation_id)
            }
            None => {
                debug!(
                    owner = %owner,
                    "no organization installation found; looking up user installation"
                );
                let installation_id = self
                    .installation_id_from_path(jwt, &format!("users/{owner}/installation"))
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "no GitHub App installation found for owner '{owner}' as an organization or a user"
                        )
                    })?;
                debug!(owner = %owner, installation_id, "user installation lookup parsed");
                Ok(installation_id)
            }
        }
    }

    /// Fetches an installation id from an installation lookup path, mapping `404 Not Found` to
    /// `None` so the caller can try another path rather than failing the request.
    async fn installation_id_from_path(
        &self,
        jwt: &str,
        path: &str,
    ) -> anyhow::Result<Option<u64>> {
        let response = self
            .client
            .get(format!("{}/{}", self.api_url, path))
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .send()
            .await
            .with_context(|| format!("failed to resolve GitHub App installation via '{path}'"))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let installation: RepositoryInstallationResponse = response
            .error_for_status()
            .with_context(|| {
                format!("GitHub App installation lookup '{path}' returned an error status")
            })?
            .json()
            .await
            .with_context(|| {
                format!("failed to parse GitHub App installation lookup response for '{path}'")
            })?;
        Ok(Some(installation.id))
    }

    async fn cached_installation_id(
        &self,
        jwt: &str,
        github_app_name: &str,
        target: &InstallationTarget,
    ) -> anyhow::Result<u64> {
        let cache_key = format!("{github_app_name}/{}", target.cache_key());
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
                target = %target,
                installation_id,
                "using cached GitHub App installation id"
            );
            return Ok(installation_id);
        }
        debug!(
            github_app = %github_app_name,
            target = %target,
            "cached GitHub App installation id not found"
        );
        let installation_id = self.installation_id(jwt, target).await?;
        self.cache
            .lock()
            .await
            .installation_ids
            .insert(cache_key, installation_id);
        debug!(
            github_app = %github_app_name,
            target = %target,
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
    use super::{GithubClient, InstallationTarget, build_create_installation_token_request};
    use crate::config::GithubAppConfig;
    use crate::service::{RepoScope, TokenScope};
    use crate::signer::Signer;
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
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

    /// One recorded call to the stub's access-token endpoint.
    struct StubTokenRequest {
        installation_id: u64,
        body: serde_json::Value,
    }

    /// Stub GitHub API that resolves installation ids and mints a uniquely-numbered token on each
    /// POST. `mint_count` makes a cache hit (which skips the POST) observable, and `token_requests`
    /// records what idcat actually asked GitHub for.
    struct StubGithubApi {
        url: String,
        mint_count: Arc<AtomicUsize>,
        token_requests: Arc<StdMutex<Vec<StubTokenRequest>>>,
    }

    const STUB_REPOSITORY_INSTALLATION_ID: u64 = 123;
    const STUB_ORGANIZATION_INSTALLATION_ID: u64 = 456;
    const STUB_USER_INSTALLATION_ID: u64 = 789;

    /// Spawns a [`StubGithubApi`]. `organizations` names the accounts served by
    /// `/orgs/{org}/installation`; any other account gets a 404 there and is served by
    /// `/users/{username}/installation`, mirroring how GitHub splits organization and user
    /// installations.
    async fn spawn_stub_github_api(organizations: &[&str]) -> StubGithubApi {
        use axum::Json;
        use axum::extract::Path;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum::routing::{get, post};

        let organizations: Arc<Vec<String>> =
            Arc::new(organizations.iter().map(|org| org.to_string()).collect());
        let mint_count = Arc::new(AtomicUsize::new(0));
        let token_requests = Arc::new(StdMutex::new(Vec::new()));
        let mint_count_for_handler = mint_count.clone();
        let token_requests_for_handler = token_requests.clone();
        let app = axum::Router::new()
            .route(
                "/repos/{owner}/{repo}/installation",
                get(|| async {
                    Json(serde_json::json!({ "id": STUB_REPOSITORY_INSTALLATION_ID }))
                }),
            )
            .route(
                "/orgs/{org}/installation",
                get(move |Path(org): Path<String>| {
                    let organizations = organizations.clone();
                    async move {
                        if organizations.contains(&org) {
                            Json(serde_json::json!({ "id": STUB_ORGANIZATION_INSTALLATION_ID }))
                                .into_response()
                        } else {
                            (
                                StatusCode::NOT_FOUND,
                                Json(serde_json::json!({ "message": "Not Found" })),
                            )
                                .into_response()
                        }
                    }
                }),
            )
            .route(
                "/users/{username}/installation",
                get(|| async { Json(serde_json::json!({ "id": STUB_USER_INSTALLATION_ID })) }),
            )
            .route(
                "/app/installations/{id}/access_tokens",
                post(
                    move |Path(installation_id): Path<u64>, Json(body): Json<serde_json::Value>| {
                        let mint_count = mint_count_for_handler.clone();
                        let token_requests = token_requests_for_handler.clone();
                        async move {
                            let n = mint_count.fetch_add(1, Ordering::SeqCst) + 1;
                            token_requests.lock().unwrap().push(StubTokenRequest {
                                installation_id,
                                body,
                            });
                            Json(serde_json::json!({
                                "token": format!("ghs_token_{n}"),
                                "expires_at": "2099-01-01T00:00:00Z",
                            }))
                        }
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        StubGithubApi {
            url: format!("http://{addr}"),
            mint_count,
            token_requests,
        }
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

    fn repository_target() -> InstallationTarget {
        InstallationTarget::Repository("myorg/alfa".to_string())
    }

    fn owner_target() -> InstallationTarget {
        InstallationTarget::Owner("myorg".to_string())
    }

    #[tokio::test]
    async fn narrow_caller_is_not_served_a_cached_broad_token() {
        let stub = spawn_stub_github_api(&["myorg"]).await;
        let mut client = GithubClient::new().unwrap();
        client.api_url = stub.url;
        let github_app = test_github_app();

        // A broad-scoped caller mints and caches a token for the repo first.
        let broad = client
            .create_installation_token(
                &github_app,
                &StubSigner,
                &repository_target(),
                broad_scope(),
            )
            .await
            .unwrap();
        // A caller authorized only for the requested repo then asks for the same
        // repo. It must get its own freshly-minted, repo-scoped token — not the
        // cached broad token covering the whole installation.
        let narrow = client
            .create_installation_token(
                &github_app,
                &StubSigner,
                &repository_target(),
                narrow_scope(&[]),
            )
            .await
            .unwrap();

        assert_ne!(
            broad.token, narrow.token,
            "narrow caller received the cached broad-scoped token"
        );
        assert_eq!(
            stub.mint_count.load(Ordering::SeqCst),
            2,
            "each scope must mint its own token rather than share a cache entry"
        );
    }

    #[tokio::test]
    async fn caller_is_not_served_a_cached_token_with_different_permissions() {
        let stub = spawn_stub_github_api(&["myorg"]).await;
        let mut client = GithubClient::new().unwrap();
        client.api_url = stub.url;
        let github_app = test_github_app();

        // A read-only caller mints and caches a token for the repo.
        let read = client
            .create_installation_token(
                &github_app,
                &StubSigner,
                &repository_target(),
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
                &repository_target(),
                narrow_scope(&[("contents", "write")]),
            )
            .await
            .unwrap();

        assert_ne!(
            read.token, write.token,
            "write caller received the cached read-only token"
        );
        assert_eq!(
            stub.mint_count.load(Ordering::SeqCst),
            2,
            "each permission set must mint its own token rather than share a cache entry"
        );
    }

    #[tokio::test]
    async fn owner_target_resolves_the_organization_installation() {
        let stub = spawn_stub_github_api(&["myorg"]).await;
        let mut client = GithubClient::new().unwrap();
        client.api_url = stub.url;

        client
            .create_installation_token(
                &test_github_app(),
                &StubSigner,
                &owner_target(),
                TokenScope {
                    repositories: RepoScope::All,
                    permissions: [("packages".to_string(), "read".to_string())]
                        .into_iter()
                        .collect(),
                },
            )
            .await
            .unwrap();

        let requests = stub.token_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].installation_id, STUB_ORGANIZATION_INSTALLATION_ID,
            "an owner target must resolve the installation through the account, not a repository"
        );
        assert_eq!(
            requests[0].body,
            serde_json::json!({ "permissions": { "packages": "read" } }),
            "an owner token must omit repositories and carry only the policy's permissions"
        );
    }

    #[tokio::test]
    async fn owner_target_falls_back_to_the_user_installation() {
        // `noa` is not an organization, so `/orgs/noa/installation` 404s.
        let stub = spawn_stub_github_api(&["myorg"]).await;
        let mut client = GithubClient::new().unwrap();
        client.api_url = stub.url;

        client
            .create_installation_token(
                &test_github_app(),
                &StubSigner,
                &InstallationTarget::Owner("noa".to_string()),
                broad_scope(),
            )
            .await
            .unwrap();

        let requests = stub.token_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].installation_id, STUB_USER_INSTALLATION_ID,
            "a user-owned account must fall back to the user installation lookup"
        );
    }

    #[tokio::test]
    async fn owner_and_repository_targets_do_not_share_a_cache_entry() {
        let stub = spawn_stub_github_api(&["myorg"]).await;
        let mut client = GithubClient::new().unwrap();
        client.api_url = stub.url;
        let github_app = test_github_app();

        let repo_wide = client
            .create_installation_token(
                &github_app,
                &StubSigner,
                &repository_target(),
                broad_scope(),
            )
            .await
            .unwrap();
        let owner_wide = client
            .create_installation_token(&github_app, &StubSigner, &owner_target(), broad_scope())
            .await
            .unwrap();

        assert_ne!(repo_wide.token, owner_wide.token);
        assert_eq!(
            stub.mint_count.load(Ordering::SeqCst),
            2,
            "an owner request must not be served a token cached for a repository request"
        );
    }

    #[test]
    fn build_create_installation_token_request_broad_omits_repositories() {
        let request =
            build_create_installation_token_request(&broad_scope(), &repository_target()).unwrap();
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json, serde_json::json!({}));
    }

    #[test]
    fn build_create_installation_token_request_narrow_sets_repository_by_name() {
        let request =
            build_create_installation_token_request(&narrow_scope(&[]), &repository_target())
                .unwrap();
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json, serde_json::json!({ "repositories": ["alfa"] }));
    }

    #[test]
    fn build_create_installation_token_request_narrow_includes_permissions() {
        let request = build_create_installation_token_request(
            &narrow_scope(&[("contents", "read")]),
            &repository_target(),
        )
        .unwrap();
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "repositories": ["alfa"], "permissions": { "contents": "read" } })
        );
    }

    #[test]
    fn build_create_installation_token_request_rejects_a_repo_scope_on_an_owner_target() {
        // Reachable only through a programming error, but silently widening the token to the whole
        // installation is exactly the confusion the owner endpoint exists to avoid.
        let error = build_create_installation_token_request(&narrow_scope(&[]), &owner_target())
            .unwrap_err();
        assert!(
            error.to_string().contains("no repository was requested"),
            "unexpected error: {error}"
        );
    }
}
