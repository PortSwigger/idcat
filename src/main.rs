// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

mod config;
mod error;
mod github;
mod jwt;
#[cfg(feature = "kms")]
#[allow(dead_code)]
mod kms;
mod nats;
mod secret;
mod service;
mod signer;
mod webhook;

use crate::config::Config;
use crate::error::AppError;
use crate::github::InstallationTokenResponse;
use crate::service::{AppState, build_app_state};
use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode, Uri, header};
use axum::response::Response;
use axum::routing::{any, get, post};
use axum::{Json, Router};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
struct Cli {
    #[arg(
        name = "config-file",
        short = 'c',
        long = "config-file",
        default_value = "/config/idcat.toml"
    )]
    config_path: String,
    #[arg(long = "disable-auth", default_value_t = false)]
    disable_auth: bool,
    #[arg(long = "debug", default_value_t = false)]
    debug: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let log_filter = if cli.debug {
        "idcat=debug,tower_http=info,axum::rejection=trace"
    } else {
        "idcat=info,tower_http=info,axum::rejection=info"
    };
    tracing_subscriber::registry()
        .with(EnvFilter::new(log_filter))
        .with(tracing_subscriber::fmt::layer().json().with_ansi(false))
        .init();

    if let Err(error) = run(cli).await {
        error!("{error:#}");
        std::process::exit(1);
    }

    Ok(())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load(&cli.config_path)?;
    config.validate(cli.disable_auth)?;
    let bind_address: SocketAddr = config.bind_address.parse()?;

    info!(
        version = VERSION,
        config_path = %cli.config_path,
        disable_auth = cli.disable_auth,
        debug = cli.debug,
        "starting idcat"
    );

    let state = build_app_state(&config, cli.disable_auth).await?;

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/webhook/{github_app}", post(webhook))
        .route(
            "/installation-token/{github_app}/{owner}/{repo}",
            post(installation_token),
        )
        .route(
            "/installation-token/{github_app}/{owner}",
            post(installation_token_for_repositories),
        )
        .route(
            "/proxy/{github_app}/repos/{owner}/{repo}",
            any(proxy_repo_root),
        )
        .route(
            "/proxy/{github_app}/repos/{owner}/{repo}/{*repo_path}",
            any(proxy_repo_path),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    info!(address = %bind_address, "listening");

    tokio::select! {
        result = axum::serve(listener, app) => {
            result?;
        }
        signal = termination_signal() => {
            let signal = signal?;
            info!(signal, "caught signal, exiting");
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn termination_signal() -> anyhow::Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = sigterm.recv() => Ok("SIGTERM"),
        result = tokio::signal::ctrl_c() => {
            result?;
            Ok("SIGINT")
        }
    }
}

#[cfg(not(unix))]
async fn termination_signal() -> anyhow::Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("SIGINT")
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn webhook(
    Path(github_app_name): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let github_app = state.github_app(&github_app_name)?;
    let webhook_target = github_app.webhook_target;
    let webhook_validation_secret_file = github_app.webhook_validation_secret_file.clone();

    if let Some(secret_file) = &webhook_validation_secret_file {
        webhook::validate_delivery(secret_file, &headers, &body).await?;
    }

    match std::str::from_utf8(&body) {
        Ok(payload) => info!(github_app = %github_app_name, "github webhook received:\n{payload}"),
        Err(_) => info!(
            github_app = %github_app_name,
            payload = ?body,
            "github webhook received non-UTF-8 payload"
        ),
    }
    if matches!(webhook_target, Some(config::WebhookTarget::Nats))
        && let Some(publisher) = &state.webhook_publisher
    {
        let github_event = nats::github_header(&headers, "x-github-event").unwrap_or("unknown");
        let github_delivery =
            nats::github_header(&headers, "x-github-delivery").unwrap_or("unknown");
        match publisher.publish_github_webhook(&headers, body).await {
            Ok(subject) => info!(
                github_app = %github_app_name,
                github_event,
                github_delivery,
                subject,
                "published github webhook to nats"
            ),
            Err(error) => warn!(
                github_app = %github_app_name,
                github_event,
                github_delivery,
                error = %error,
                "failed to publish github webhook to nats"
            ),
        }
    }
    Ok(StatusCode::ACCEPTED)
}

async fn installation_token(
    Path((github_app, owner, repo)): Path<(String, String, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    let repo = format!("{owner}/{repo}");
    let token = create_installation_token_for_repo(&github_app, &repo, &state, &headers).await?;
    Ok(token.token)
}

const MAX_TOKEN_REPOSITORIES: usize = 500;

#[derive(Debug, Deserialize)]
struct MultipleRepositoriesTokenRequest {
    repositories: Vec<String>,
    permissions: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct MultipleRepositoriesTokenResponse {
    #[serde(flatten)]
    installation_token: InstallationTokenResponse,
    repositories: Vec<String>,
}

async fn installation_token_for_repositories(
    Path((github_app_name, owner)): Path<(String, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MultipleRepositoriesTokenRequest>,
) -> Result<Json<MultipleRepositoriesTokenResponse>, AppError> {
    validate_repository_names(&request.repositories)?;
    let bearer_token = request_bearer_token(&state, &headers)?;
    let github_app = state.github_app(&github_app_name)?;
    let repositories: Vec<String> = request
        .repositories
        .iter()
        .map(|repo| format!("{owner}/{repo}"))
        .collect();
    let scopes = repositories
        .iter()
        .map(|repo| state.authorize_github_app(github_app, repo, bearer_token.as_deref()))
        .collect::<Result<Vec<_>, _>>()?;
    let permissions = select_multiple_repository_permissions(request.permissions, &scopes)?;
    let signer = state.signer(&github_app.secret_key)?;
    let token = state
        .github
        .create_installation_token_for_multiple_repositories(
            github_app,
            signer.as_ref(),
            repositories,
            permissions,
        )
        .await?;
    Ok(Json(MultipleRepositoriesTokenResponse {
        installation_token: token,
        repositories: request
            .repositories
            .into_iter()
            .map(|repo| format!("{owner}/{repo}"))
            .collect(),
    }))
}

fn validate_repository_names(repositories: &[String]) -> Result<(), AppError> {
    if repositories.is_empty() {
        return Err(AppError::BadRequest(
            "repositories must contain at least one repository".to_string(),
        ));
    }
    if repositories.len() > MAX_TOKEN_REPOSITORIES {
        return Err(AppError::BadRequest(format!(
            "repositories must contain no more than {MAX_TOKEN_REPOSITORIES} repositories"
        )));
    }
    let mut unique = BTreeSet::new();
    for repository in repositories {
        if repository.is_empty() || repository.contains('/') {
            return Err(AppError::BadRequest(format!(
                "repository '{repository}' must be a repository name without an owner"
            )));
        }
        if !unique.insert(repository) {
            return Err(AppError::BadRequest(format!(
                "repository '{repository}' is listed more than once"
            )));
        }
    }
    Ok(())
}

fn select_multiple_repository_permissions(
    requested: Option<BTreeMap<String, String>>,
    scopes: &[crate::service::TokenScope],
) -> Result<BTreeMap<String, String>, AppError> {
    if let Some(requested) = requested {
        if requested.is_empty() {
            return Err(AppError::BadRequest(
                "permissions must not be empty when specified".to_string(),
            ));
        }
        for scope in scopes {
            ensure_permissions_allowed(&requested, &scope.permissions)?;
        }
        return Ok(requested);
    }

    let mut restricted = scopes
        .iter()
        .map(|scope| &scope.permissions)
        .filter(|permissions| !permissions.is_empty());
    let Some(first) = restricted.next() else {
        return Ok(BTreeMap::new());
    };
    if restricted.any(|permissions| permissions != first) {
        return Err(AppError::BadRequest(
            "repositories have different permission policies; specify permissions explicitly"
                .to_string(),
        ));
    }
    Ok(first.clone())
}

fn ensure_permissions_allowed(
    requested: &BTreeMap<String, String>,
    allowed: &BTreeMap<String, String>,
) -> Result<(), AppError> {
    if allowed.is_empty() {
        return Ok(());
    }
    for (permission, requested_level) in requested {
        let Some(allowed_level) = allowed.get(permission) else {
            return Err(AppError::Unauthorized(format!(
                "permission '{permission}' is not allowed by every matching installation policy"
            )));
        };
        if !permission_level_is_at_most(requested_level, allowed_level) {
            return Err(AppError::Unauthorized(format!(
                "permission '{permission}' level '{requested_level}' exceeds allowed level '{allowed_level}'"
            )));
        }
    }
    Ok(())
}

fn permission_level_is_at_most(requested: &str, allowed: &str) -> bool {
    fn rank(level: &str) -> Option<u8> {
        match level {
            "read" => Some(1),
            "write" => Some(2),
            "admin" => Some(3),
            _ => None,
        }
    }
    match (rank(requested), rank(allowed)) {
        (Some(requested), Some(allowed)) => requested <= allowed,
        _ => requested == allowed,
    }
}

async fn proxy_repo_root(
    Path((github_app, owner, repo)): Path<(String, String, String)>,
    State(state): State<AppState>,
    OriginalUri(original_uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    proxy_repo_request(ProxyRepoRequest {
        github_app,
        owner,
        repo_name: repo,
        repo_path: None,
        state,
        original_uri,
        method,
        headers,
        body,
    })
    .await
}

async fn proxy_repo_path(
    Path((github_app, owner, repo, repo_path)): Path<(String, String, String, String)>,
    State(state): State<AppState>,
    OriginalUri(original_uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    proxy_repo_request(ProxyRepoRequest {
        github_app,
        owner,
        repo_name: repo,
        repo_path: Some(repo_path),
        state,
        original_uri,
        method,
        headers,
        body,
    })
    .await
}

struct ProxyRepoRequest {
    github_app: String,
    owner: String,
    repo_name: String,
    repo_path: Option<String>,
    state: AppState,
    original_uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
}

async fn proxy_repo_request(request: ProxyRepoRequest) -> Result<Response, AppError> {
    let ProxyRepoRequest {
        github_app,
        owner,
        repo_name,
        repo_path,
        state,
        original_uri,
        method,
        headers,
        body,
    } = request;
    let repo = format!("{owner}/{repo_name}");
    let github_path = match repo_path {
        Some(repo_path) => format!("repos/{repo}/{repo_path}"),
        None => format!("repos/{repo}"),
    };
    debug!(
        github_app = %github_app,
        repo = %repo,
        github_path = %github_path,
        method = %method,
        "proxy request received"
    );
    let token = create_installation_token_for_repo(&github_app, &repo, &state, &headers).await?;
    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|error| AppError::Internal(format!("failed to convert HTTP method: {error}")))?;
    let upstream_response = state
        .github
        .proxy_request(
            reqwest_method,
            &github_path,
            original_uri.query(),
            &headers,
            body.to_vec(),
            &token.token,
        )
        .await?;
    let status = upstream_response.status();
    let upstream_headers = upstream_response.headers().clone();
    let upstream_body = upstream_response
        .bytes()
        .await
        .map_err(|error| AppError::Internal(format!("failed to read proxied response: {error}")))?;
    debug!(
        github_app = %github_app,
        repo = %repo,
        github_path = %github_path,
        status = status.as_u16(),
        "proxy response received"
    );
    let mut response = Response::builder().status(status);
    for (name, value) in upstream_headers.iter() {
        if should_return_proxy_header(name) {
            response = response.header(name, value);
        }
    }
    response
        .body(Body::from(upstream_body))
        .map_err(|error| AppError::Internal(format!("failed to build proxied response: {error}")))
}

async fn create_installation_token_for_repo(
    github_app_name: &str,
    repo: &str,
    state: &AppState,
    headers: &HeaderMap,
) -> Result<InstallationTokenResponse, AppError> {
    debug!(github_app = %github_app_name, repo = %repo, "installation token flow started");
    let bearer_token = request_bearer_token(state, headers)?;
    debug!(github_app = %github_app_name, repo = %repo, "selecting GitHub App config");
    let github_app = state.github_app(github_app_name)?;
    let token_scope = state.authorize_github_app(github_app, repo, bearer_token.as_deref())?;
    debug!(github_app = %github_app_name, repo = %repo, secret_key = %github_app.secret_key, key_source = ?state.key_source, ?token_scope, "preparing GitHub App signer");
    let signer = state.signer(&github_app.secret_key)?;
    debug!(github_app = %github_app_name, repo = %repo, ?token_scope, "requesting GitHub installation access token");
    let token = state
        .github
        .create_installation_token(github_app, signer.as_ref(), repo, token_scope)
        .await?;
    debug!(github_app = %github_app_name, repo = %repo, expires_at = %token.expires_at, "GitHub installation access token created");
    Ok(token)
}

fn request_bearer_token(state: &AppState, headers: &HeaderMap) -> Result<Option<String>, AppError> {
    match extract_bearer_token(headers) {
        Ok(token) => Ok(Some(token)),
        Err(_) if !state.token_validator.auth_enabled() => Ok(None),
        Err(error) => Err(error),
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, AppError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
    let value = value
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid Authorization header".to_string()))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("expected a Bearer token".to_string()))?;
    if token.is_empty() {
        return Err(AppError::Unauthorized("empty bearer token".to_string()));
    }
    Ok(token.to_string())
}

fn should_return_proxy_header(name: &HeaderName) -> bool {
    !matches!(
        name,
        &header::CONNECTION
            | &header::PROXY_AUTHENTICATE
            | &header::PROXY_AUTHORIZATION
            | &header::TE
            | &header::TRAILER
            | &header::TRANSFER_ENCODING
            | &header::UPGRADE
    )
}

#[cfg(test)]
mod tests {
    use super::{
        permission_level_is_at_most, select_multiple_repository_permissions,
        validate_repository_names, webhook,
    };
    use crate::config::{GithubAppConfig, KeySource};
    use crate::error::AppError;
    use crate::github::GithubClient;
    use crate::secret::FilePrivateKeyStore;
    use crate::service::{AppState, RepoScope, TokenScope, TokenValidator};
    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_state(github_apps: Vec<GithubAppConfig>) -> AppState {
        AppState {
            github_apps: Arc::new(github_apps),
            installation_policies: Arc::new(Vec::new()),
            token_validator: TokenValidator::new(Vec::new(), true).unwrap(),
            github: GithubClient::new().unwrap(),
            webhook_publisher: None,
            key_source: KeySource::Local,
            private_key_store: FilePrivateKeyStore::new("/var/run/secrets/idcat"),
            #[cfg(feature = "kms")]
            kms_signers: None,
        }
    }

    fn test_github_app(webhook_validation_secret_file: Option<String>) -> GithubAppConfig {
        GithubAppConfig {
            name: "default".to_string(),
            app_id: 42,
            secret_key: "private-key.pem".to_string(),
            webhook_target: None,
            webhook_validation_secret_file,
            allowed_roles: Vec::new(),
        }
    }

    #[tokio::test]
    async fn webhook_accepts_github_payload() {
        let status = webhook(
            Path("default".to_string()),
            State(test_state(vec![test_github_app(None)])),
            HeaderMap::new(),
            Bytes::from_static(br#"{"zen":"Keep it logically awesome."}"#),
        )
        .await
        .unwrap();

        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn webhook_rejects_unknown_github_app() {
        let error = webhook(
            Path("missing".to_string()),
            State(test_state(vec![test_github_app(None)])),
            HeaderMap::new(),
            Bytes::from_static(br#"{"zen":"Keep it logically awesome."}"#),
        )
        .await
        .unwrap_err();

        assert!(matches!(error, AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn webhook_rejects_delivery_with_missing_signature_when_validation_configured() {
        let mut secret_file = std::env::temp_dir();
        secret_file.push("idcat-webhook-secret-missing-signature");
        std::fs::write(&secret_file, "It's a Secret to Everybody").unwrap();

        let error = webhook(
            Path("default".to_string()),
            State(test_state(vec![test_github_app(Some(
                secret_file.to_string_lossy().into_owned(),
            ))])),
            HeaderMap::new(),
            Bytes::from_static(b"Hello, World!"),
        )
        .await
        .unwrap_err();

        std::fs::remove_file(&secret_file).ok();
        assert!(matches!(error, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn webhook_accepts_delivery_with_valid_signature() {
        let mut secret_file = std::env::temp_dir();
        secret_file.push("idcat-webhook-secret-valid-signature");
        std::fs::write(&secret_file, "It's a Secret to Everybody").unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-hub-signature-256",
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
                .parse()
                .unwrap(),
        );

        let status = webhook(
            Path("default".to_string()),
            State(test_state(vec![test_github_app(Some(
                secret_file.to_string_lossy().into_owned(),
            ))])),
            headers,
            Bytes::from_static(b"Hello, World!"),
        )
        .await
        .unwrap();

        std::fs::remove_file(&secret_file).ok();
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    fn token_scope(permissions: &[(&str, &str)]) -> TokenScope {
        TokenScope {
            repositories: RepoScope::OnlyRequested,
            permissions: permissions
                .iter()
                .map(|(name, level)| (name.to_string(), level.to_string()))
                .collect(),
        }
    }

    #[test]
    fn validates_multiple_repository_names() {
        validate_repository_names(&["alfa".to_string(), "bravo".to_string()]).unwrap();

        assert!(validate_repository_names(&[]).is_err());
        assert!(validate_repository_names(&["myorg/alfa".to_string()]).is_err());
        assert!(validate_repository_names(&["alfa".to_string(), "alfa".to_string()]).is_err());
    }

    #[test]
    fn explicit_permissions_must_be_allowed_for_every_repository() {
        let requested = BTreeMap::from([("contents".to_string(), "write".to_string())]);
        let scopes = vec![
            token_scope(&[("contents", "write")]),
            token_scope(&[("contents", "read")]),
        ];

        assert!(select_multiple_repository_permissions(Some(requested), &scopes).is_err());
    }

    #[test]
    fn explicit_permissions_can_downscope_every_repository() {
        let requested = BTreeMap::from([("contents".to_string(), "read".to_string())]);
        let scopes = vec![
            token_scope(&[("contents", "write")]),
            token_scope(&[("contents", "read")]),
        ];

        assert_eq!(
            select_multiple_repository_permissions(Some(requested.clone()), &scopes).unwrap(),
            requested
        );
    }

    #[test]
    fn omitted_permissions_use_shared_restricted_policy() {
        let expected = BTreeMap::from([("contents".to_string(), "read".to_string())]);
        let scopes = vec![
            token_scope(&[]),
            token_scope(&[("contents", "read")]),
            token_scope(&[("contents", "read")]),
        ];

        assert_eq!(
            select_multiple_repository_permissions(None, &scopes).unwrap(),
            expected
        );
    }

    #[test]
    fn omitted_permissions_reject_different_restricted_policies() {
        let scopes = vec![
            token_scope(&[("contents", "read")]),
            token_scope(&[("issues", "write")]),
        ];

        assert!(select_multiple_repository_permissions(None, &scopes).is_err());
    }

    #[test]
    fn permission_levels_are_ordered() {
        assert!(permission_level_is_at_most("read", "write"));
        assert!(permission_level_is_at_most("write", "admin"));
        assert!(!permission_level_is_at_most("write", "read"));
        assert!(permission_level_is_at_most("custom", "custom"));
        assert!(!permission_level_is_at_most("custom", "read"));
    }
}
