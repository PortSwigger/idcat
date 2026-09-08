// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::config::{
    Config, GithubAppConfig, HumanPolicyConfig, HumanRoleConfig, InstallationPolicyConfig,
    KeySource, WebhookTarget,
};
use crate::error::AppError;
use crate::github::GithubClient;
use crate::human::{HumanTokenError, HumanTokenValidator};
use crate::nats::WebhookPublisher;
use crate::secret::FilePrivateKeyStore;
use crate::signer::{LocalSigner, Signer};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::debug;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum RepoScope {
    OnlyRequested,
    All,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct TokenScope {
    pub repositories: RepoScope,
    pub permissions: BTreeMap<String, String>,
}

impl TokenScope {
    fn broad() -> Self {
        Self {
            repositories: RepoScope::All,
            permissions: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub github_apps: Arc<Vec<GithubAppConfig>>,
    pub installation_policies: Arc<Vec<InstallationPolicyConfig>>,
    pub human_policies: Arc<Vec<HumanPolicyConfig>>,
    pub human_roles: Arc<BTreeMap<String, HumanRole>>,
    pub token_validator: TokenValidator,
    pub github: GithubClient,
    pub webhook_publisher: Option<WebhookPublisher>,
    pub key_source: KeySource,
    pub private_key_store: FilePrivateKeyStore,
    #[cfg(feature = "kms")]
    pub kms_signers: Option<crate::kms::KmsSignerFactory>,
}

pub async fn build_app_state(config: &Config, disable_auth: bool) -> anyhow::Result<AppState> {
    #[cfg(feature = "kms")]
    let kms_signers = match config.key_source {
        KeySource::Local => None,
        KeySource::Kms => Some(crate::kms::KmsSignerFactory::from_env().await),
    };

    let any_nats_webhook_target = config
        .github_apps
        .iter()
        .any(|github_app| matches!(github_app.webhook_target, Some(WebhookTarget::Nats)));
    let webhook_publisher = match (any_nats_webhook_target, &config.nats) {
        (true, Some(nats)) => Some(WebhookPublisher::connect(nats).await?),
        _ => None,
    };

    Ok(AppState {
        github_apps: Arc::new(config.github_apps.clone()),
        installation_policies: Arc::new(config.installation_policies.clone()),
        human_policies: Arc::new(config.human_policies.clone()),
        human_roles: Arc::new(build_human_roles(&config.human_roles)?),
        token_validator: TokenValidator::new(config.roles.clone(), disable_auth)?,
        github: GithubClient::new()?,
        webhook_publisher,
        key_source: config.key_source,
        private_key_store: FilePrivateKeyStore::new(&config.private_key_directory),
        #[cfg(feature = "kms")]
        kms_signers,
    })
}

impl AppState {
    pub fn github_app(&self, github_app_name: &str) -> Result<&GithubAppConfig, AppError> {
        debug!(github_app = %github_app_name, "searching configured GitHub apps");
        self.github_apps
            .iter()
            .find(|github_app| github_app.name == github_app_name)
            .ok_or_else(|| AppError::NotFound(format!("unknown github_app '{github_app_name}'")))
    }

    pub fn authorize_github_app(
        &self,
        github_app: &GithubAppConfig,
        repo: &str,
        bearer_token: Option<&str>,
    ) -> Result<TokenScope, AppError> {
        if !self.token_validator.auth_enabled() {
            debug!(
                github_app = %github_app.name,
                repo = %repo,
                "skipping authorization because auth is disabled"
            );
            return Ok(TokenScope::broad());
        }
        let bearer_token = bearer_token
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
        let matching_roles = self.token_validator.validate(bearer_token);
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            ?matching_roles,
            allowed_roles = ?github_app.allowed_roles,
            "matched roles for source token"
        );
        let allowed_role_match = matching_roles.iter().any(|role| {
            github_app
                .allowed_roles
                .iter()
                .any(|allowed| allowed == role)
        });
        if allowed_role_match {
            return Ok(TokenScope::broad());
        }
        let installation_policy_match =
            self.installation_policies
                .iter()
                .find(|installation_policy| {
                    installation_policy.github_app == github_app.name
                        && installation_policy
                            .repositories
                            .iter()
                            .any(|repository| wildmatch::WildMatch::new(repository).matches(repo))
                        && self.token_validator.validate_role_with_claims(
                            &installation_policy.role,
                            &claims_for_request(installation_policy, repo),
                            bearer_token,
                        )
                });
        if let Some(installation_policy) = installation_policy_match {
            return Ok(TokenScope {
                repositories: RepoScope::OnlyRequested,
                permissions: installation_policy.permissions.clone(),
            });
        }
        Err(AppError::Unauthorized(format!(
            "source token did not match any allowed role for github-app '{}' and repository '{}'",
            github_app.name, repo
        )))
    }

    /// Authorizes a person's request for a token covering exactly `repo`.
    ///
    /// This path is deliberately not a variant of [`Self::authorize_github_app`]. It never
    /// consults `allowed-roles`, never widens the scope, and never retries against another
    /// policy: a request that does not match exactly one `[[human-policy]]` is refused. The
    /// repository is resolved from configuration *before* the token is validated and long before
    /// GitHub is contacted, so a request for the wrong repository costs no upstream call.
    pub async fn authorize_human(
        &self,
        github_app: &GithubAppConfig,
        repo: &str,
        bearer_token: Option<&str>,
    ) -> Result<(TokenScope, HumanIdentity), AppError> {
        // `--disable-auth` is a local development affordance for the workload path. Honouring it
        // here would turn the human route into an unauthenticated token minter, so it does not
        // apply: the human path has no unauthenticated mode.
        let bearer_token = bearer_token
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;

        let Some(human_policy) = self.human_policies.iter().find(|human_policy| {
            human_policy.github_app == github_app.name && human_policy.repository == repo
        }) else {
            debug!(
                github_app = %github_app.name,
                repo = %repo,
                "no human-policy names this github-app and repository"
            );
            return Err(AppError::Unauthorized(format!(
                "no human-policy authorizes github-app '{}' for repository '{}'",
                github_app.name, repo
            )));
        };

        let human_role = self
            .human_roles
            .get(&human_policy.human_role)
            .ok_or_else(|| {
                // Startup validation rejects this, so reaching it means the state was built by
                // some path that skipped validation.
                AppError::Internal(format!(
                    "human-policy references unknown human-role '{}'",
                    human_policy.human_role
                ))
            })?;

        let claims = human_role
            .validator
            .validate(
                bearer_token,
                &human_role.config.roles_claim,
                &human_role.config.teleport_role,
                &human_role.config.required_claims,
            )
            .await
            .map_err(|error| match error {
                HumanTokenError::KeysUnavailable => AppError::Internal(
                    "Teleport validation keys could not be retrieved".to_string(),
                ),
                error => {
                    debug!(
                        github_app = %github_app.name,
                        repo = %repo,
                        human_role = %human_policy.human_role,
                        error = %error,
                        "human token rejected"
                    );
                    AppError::Unauthorized(format!(
                        "token did not satisfy human-role '{}' for repository '{}'",
                        human_policy.human_role, repo
                    ))
                }
            })?;

        let identity = HumanIdentity {
            subject: claims.subject().to_string(),
            request_id: human_role
                .config
                .request_id_claim
                .as_deref()
                .and_then(|claim| claims.claim_str(claim))
                .map(str::to_string),
            human_role: human_policy.human_role.clone(),
        };

        Ok((
            TokenScope {
                repositories: RepoScope::OnlyRequested,
                permissions: human_policy.permissions.clone(),
            },
            identity,
        ))
    }

    pub fn signer(&self, secret_key: &str) -> anyhow::Result<Box<dyn Signer>> {
        match self.key_source {
            KeySource::Local => {
                let private_key_pem = self.private_key_store.private_key_pem(secret_key)?;
                Ok(Box::new(LocalSigner::from_rsa_pem(&private_key_pem)?))
            }
            KeySource::Kms => {
                #[cfg(feature = "kms")]
                {
                    let kms_signers = self
                        .kms_signers
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("AWS KMS signer factory not initialized"))?;
                    Ok(Box::new(kms_signers.signer_for_secret_key(secret_key)))
                }
                #[cfg(not(feature = "kms"))]
                {
                    anyhow::bail!(
                        "key_source 'kms' requires idcat to be built with the 'kms' feature"
                    )
                }
            }
        }
    }
}

/// Who a token is being minted for. This is part of the installation-token cache key, so a token
/// minted for one person is never handed to another, and a person's token is never served from
/// the shared workload entry.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Requester {
    /// A workload identity. These legitimately share a cache entry: the token they receive depends
    /// only on the App, repository and scope, and no person is accountable for it.
    Workload,
    /// A person. Partitioned by validated subject *and* the access request that authorised them,
    /// so a second approval for the same person yields a fresh token rather than reviving the one
    /// issued under the previous approval.
    Person {
        subject: String,
        request_id: Option<String>,
    },
}

impl Requester {
    pub fn person(identity: &HumanIdentity) -> Self {
        Self::Person {
            subject: identity.subject.clone(),
            request_id: identity.request_id.clone(),
        }
    }
}

/// A configured Teleport issuer together with the validator built for it. The validator holds the
/// JWKS cache, so it is built once at startup rather than per request.
#[derive(Clone)]
pub struct HumanRole {
    pub config: HumanRoleConfig,
    pub validator: HumanTokenValidator,
}

/// Who idcat believes is asking, carried from authorization through to the token request so that
/// the issuance record names a person and the token cache cannot be shared between people.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanIdentity {
    /// The validated `sub` of the Teleport token.
    pub subject: String,
    /// The Teleport access request or session the approval came from, when the issuer supplies it.
    pub request_id: Option<String>,
    /// The `[[human-role]]` that authorised this request.
    pub human_role: String,
}

fn build_human_roles(
    human_roles: &[HumanRoleConfig],
) -> anyhow::Result<BTreeMap<String, HumanRole>> {
    human_roles
        .iter()
        .map(|config| {
            let algorithms = config
                .algorithms
                .iter()
                .map(|algorithm| algorithm.to_algorithm())
                .collect();
            let validator = HumanTokenValidator::from_http(
                &config.issuer,
                &config.audience,
                &config.jwks_url,
                algorithms,
            )?;
            Ok((
                config.name.clone(),
                HumanRole {
                    config: config.clone(),
                    validator,
                },
            ))
        })
        .collect()
}

fn claims_for_request(
    installation_policy: &InstallationPolicyConfig,
    request_repo: &str,
) -> BTreeMap<String, authzoo::ClaimRequirement> {
    let mut claims = installation_policy.required_claims.clone();
    if installation_policy.allow_self_access {
        claims.insert(
            "repository".to_string(),
            authzoo::ClaimRequirement::equals(request_repo),
        );
    }
    claims
}

#[derive(Clone)]
pub struct TokenValidator {
    inner: Option<authzoo::TokenValidator>,
}

impl TokenValidator {
    pub fn new(roles: Vec<authzoo::RoleConfig>, disable_auth: bool) -> anyhow::Result<Self> {
        let inner = if disable_auth {
            None
        } else {
            Some(authzoo::TokenValidator::new(roles)?)
        };
        Ok(Self { inner })
    }

    pub fn validate(&self, bearer_token: &str) -> Vec<String> {
        match &self.inner {
            Some(validator) => validator.validate(bearer_token),
            None => Vec::new(),
        }
    }

    pub fn validate_role_with_claims(
        &self,
        role_name: &str,
        required_claims: &BTreeMap<String, authzoo::ClaimRequirement>,
        bearer_token: &str,
    ) -> bool {
        let Some(validator) = &self.inner else {
            return false;
        };
        let Some(role) = validator.roles().get(role_name) else {
            return false;
        };
        let mut role = role.clone();
        role.claims.extend(required_claims.clone());
        authzoo::TokenValidator::new(vec![role])
            .map(|validator| {
                validator
                    .validate(bearer_token)
                    .iter()
                    .any(|role| role == role_name)
            })
            .unwrap_or(false)
    }

    pub fn auth_enabled(&self) -> bool {
        self.inner.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::RepoScope;
    use super::{AppState, TokenValidator};
    use crate::config::{GithubAppConfig, InstallationPolicyConfig, KeySource};
    use crate::error::AppError;
    use crate::github::GithubClient;
    use crate::secret::FilePrivateKeyStore;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_state(github_apps: Vec<GithubAppConfig>) -> AppState {
        test_state_with_installation_policies(github_apps, Vec::new())
    }

    fn test_state_with_installation_policies(
        github_apps: Vec<GithubAppConfig>,
        installation_policies: Vec<InstallationPolicyConfig>,
    ) -> AppState {
        AppState {
            github_apps: Arc::new(github_apps),
            installation_policies: Arc::new(installation_policies),
            human_policies: Arc::new(Vec::new()),
            human_roles: Arc::new(BTreeMap::new()),
            token_validator: TokenValidator::new(Vec::new(), true).unwrap(),
            github: GithubClient::new().unwrap(),
            webhook_publisher: None,
            key_source: KeySource::Local,
            private_key_store: FilePrivateKeyStore::new("/var/run/secrets/idcat"),
            #[cfg(feature = "kms")]
            kms_signers: None,
        }
    }

    fn github_workflow_role() -> authzoo::RoleConfig {
        authzoo::RoleConfig {
            name: "github-workflow".to_string(),
            audience: "idcat".to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            validation_key: Some("secret".to_string()),
            algorithms: vec![authzoo::JwtAlgorithm::Hs256],
            claims: BTreeMap::new(),
        }
    }

    #[derive(Serialize)]
    struct TestClaims<'a> {
        sub: &'a str,
        aud: &'a str,
        iss: &'a str,
        exp: u64,
        repository: &'a str,
    }

    fn github_workflow_token(repository: &str) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &TestClaims {
                sub: "repo:myorg/gamma:ref:refs/heads/main",
                aud: "idcat",
                iss: "https://token.actions.githubusercontent.com",
                exp: 4_102_444_800,
                repository,
            },
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap()
    }

    #[test]
    fn github_app_returns_matching_config() {
        let state = test_state(vec![GithubAppConfig {
            name: "default".to_string(),
            app_id: 42,
            secret_key: "private-key.pem".to_string(),
            webhook_target: None,
            webhook_validation_secret_file: None,
            allowed_roles: vec!["buildkite-deploy".to_string()],
        }]);

        let github_app = state.github_app("default").unwrap();
        assert_eq!(
            github_app.allowed_roles,
            vec!["buildkite-deploy".to_string()]
        );
    }

    #[test]
    fn authorize_github_app_passes_when_auth_disabled() {
        let state = test_state(vec![GithubAppConfig {
            name: "default".to_string(),
            app_id: 42,
            secret_key: "private-key.pem".to_string(),
            webhook_target: None,
            webhook_validation_secret_file: None,
            allowed_roles: Vec::new(),
        }]);

        let github_app = state.github_app("default").unwrap().clone();
        state
            .authorize_github_app(&github_app, "myorg/alfa", None)
            .unwrap();
    }

    #[test]
    fn authorize_github_app_requires_bearer_token_when_auth_enabled() {
        let mut state = test_state(vec![GithubAppConfig {
            name: "default".to_string(),
            app_id: 42,
            secret_key: "private-key.pem".to_string(),
            webhook_target: None,
            webhook_validation_secret_file: None,
            allowed_roles: vec!["kubernetes-default".to_string()],
        }]);
        state.token_validator = TokenValidator::new(Vec::new(), false).unwrap();

        let github_app = state.github_app("default").unwrap().clone();
        let error = state
            .authorize_github_app(&github_app, "myorg/alfa", None)
            .unwrap_err();
        assert!(matches!(error, AppError::Unauthorized(_)));
    }

    #[test]
    fn authorize_github_app_accepts_installation_policy_with_required_claims() {
        let mut required_claims = BTreeMap::new();
        required_claims.insert(
            "repository".to_string(),
            authzoo::ClaimRequirement::equals("myorg/gamma"),
        );
        let mut state = test_state_with_installation_policies(
            vec![GithubAppConfig {
                name: "default".to_string(),
                app_id: 42,
                secret_key: "private-key.pem".to_string(),
                webhook_target: None,
                webhook_validation_secret_file: None,
                allowed_roles: Vec::new(),
            }],
            vec![InstallationPolicyConfig {
                github_app: "default".to_string(),
                repositories: vec!["myorg/alfa".to_string()],
                role: "github-workflow".to_string(),
                required_claims,
                allow_self_access: false,
                permissions: BTreeMap::new(),
            }],
        );
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("myorg/gamma");
        let github_app = state.github_app("default").unwrap().clone();
        state
            .authorize_github_app(&github_app, "myorg/alfa", Some(&token))
            .unwrap();
    }

    #[test]
    fn authorize_github_app_rejects_installation_policy_when_required_claims_do_not_match() {
        let mut required_claims = BTreeMap::new();
        required_claims.insert(
            "repository".to_string(),
            authzoo::ClaimRequirement::equals("myorg/gamma"),
        );
        let mut state = test_state_with_installation_policies(
            vec![GithubAppConfig {
                name: "default".to_string(),
                app_id: 42,
                secret_key: "private-key.pem".to_string(),
                webhook_target: None,
                webhook_validation_secret_file: None,
                allowed_roles: Vec::new(),
            }],
            vec![InstallationPolicyConfig {
                github_app: "default".to_string(),
                repositories: vec!["myorg/alfa".to_string()],
                role: "github-workflow".to_string(),
                required_claims,
                allow_self_access: false,
                permissions: BTreeMap::new(),
            }],
        );
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("myorg/epsilon");
        let github_app = state.github_app("default").unwrap().clone();
        let error = state
            .authorize_github_app(&github_app, "myorg/alfa", Some(&token))
            .unwrap_err();
        assert!(matches!(error, AppError::Unauthorized(_)));
    }

    #[test]
    fn authorize_github_app_returns_broad_when_matched_via_allowed_roles() {
        let mut state = test_state(vec![GithubAppConfig {
            name: "default".to_string(),
            app_id: 42,
            secret_key: "private-key.pem".to_string(),
            webhook_target: None,
            webhook_validation_secret_file: None,
            allowed_roles: vec!["github-workflow".to_string()],
        }]);
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("myorg/anything");
        let github_app = state.github_app("default").unwrap().clone();
        let scope = state
            .authorize_github_app(&github_app, "myorg/alfa", Some(&token))
            .unwrap();
        assert_eq!(scope.repositories, RepoScope::All);
        assert!(scope.permissions.is_empty());
    }

    #[test]
    fn authorize_github_app_returns_narrow_when_matched_via_installation_policy() {
        let mut state = test_state_with_installation_policies(
            vec![GithubAppConfig {
                name: "default".to_string(),
                app_id: 42,
                secret_key: "private-key.pem".to_string(),
                webhook_target: None,
                webhook_validation_secret_file: None,
                allowed_roles: Vec::new(),
            }],
            vec![workflow_self_scoping_policy()],
        );
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("myorg/alfa");
        let github_app = state.github_app("default").unwrap().clone();
        let scope = state
            .authorize_github_app(&github_app, "myorg/alfa", Some(&token))
            .unwrap();
        assert_eq!(scope.repositories, RepoScope::OnlyRequested);
        assert!(scope.permissions.is_empty());
    }

    #[test]
    fn authorize_github_app_matches_any_repository_in_installation_policy() {
        let mut policy = workflow_self_scoping_policy();
        policy.repositories = vec!["myorg/bravo".to_string(), "myorg/alfa".to_string()];
        let mut state = test_state_with_installation_policies(
            vec![GithubAppConfig {
                name: "default".to_string(),
                app_id: 42,
                secret_key: "private-key.pem".to_string(),
                webhook_target: None,
                webhook_validation_secret_file: None,
                allowed_roles: Vec::new(),
            }],
            vec![policy],
        );
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("myorg/alfa");
        let github_app = state.github_app("default").unwrap().clone();
        let scope = state
            .authorize_github_app(&github_app, "myorg/alfa", Some(&token))
            .unwrap();
        assert_eq!(scope.repositories, RepoScope::OnlyRequested);
    }

    #[test]
    fn authorize_github_app_threads_permissions_from_installation_policy() {
        let mut policy = workflow_self_scoping_policy();
        policy
            .permissions
            .insert("contents".to_string(), "read".to_string());
        let mut state = test_state_with_installation_policies(
            vec![GithubAppConfig {
                name: "default".to_string(),
                app_id: 42,
                secret_key: "private-key.pem".to_string(),
                webhook_target: None,
                webhook_validation_secret_file: None,
                allowed_roles: Vec::new(),
            }],
            vec![policy],
        );
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("myorg/alfa");
        let github_app = state.github_app("default").unwrap().clone();
        let scope = state
            .authorize_github_app(&github_app, "myorg/alfa", Some(&token))
            .unwrap();
        assert_eq!(scope.repositories, RepoScope::OnlyRequested);
        assert_eq!(
            scope.permissions.get("contents").map(String::as_str),
            Some("read")
        );
    }

    fn workflow_self_scoping_policy() -> InstallationPolicyConfig {
        InstallationPolicyConfig {
            github_app: "default".to_string(),
            repositories: vec!["myorg/*".to_string()],
            role: "github-workflow".to_string(),
            required_claims: BTreeMap::new(),
            allow_self_access: true,
            permissions: BTreeMap::new(),
        }
    }

    #[test]
    fn authorize_github_app_accepts_workflow_self_scoping_when_claim_matches_request_repo() {
        let mut state = test_state_with_installation_policies(
            vec![GithubAppConfig {
                name: "default".to_string(),
                app_id: 42,
                secret_key: "private-key.pem".to_string(),
                webhook_target: None,
                webhook_validation_secret_file: None,
                allowed_roles: Vec::new(),
            }],
            vec![workflow_self_scoping_policy()],
        );
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("myorg/alfa");
        let github_app = state.github_app("default").unwrap().clone();
        state
            .authorize_github_app(&github_app, "myorg/alfa", Some(&token))
            .unwrap();
    }

    #[test]
    fn authorize_github_app_rejects_workflow_self_scoping_when_claim_disagrees_with_request_repo() {
        let mut state = test_state_with_installation_policies(
            vec![GithubAppConfig {
                name: "default".to_string(),
                app_id: 42,
                secret_key: "private-key.pem".to_string(),
                webhook_target: None,
                webhook_validation_secret_file: None,
                allowed_roles: Vec::new(),
            }],
            vec![workflow_self_scoping_policy()],
        );
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("myorg/beta");
        let github_app = state.github_app("default").unwrap().clone();
        let error = state
            .authorize_github_app(&github_app, "myorg/alfa", Some(&token))
            .unwrap_err();
        assert!(matches!(error, AppError::Unauthorized(_)));
    }

    #[test]
    fn authorize_github_app_rejects_workflow_self_scoping_when_request_repo_does_not_match_pattern()
    {
        let mut state = test_state_with_installation_policies(
            vec![GithubAppConfig {
                name: "default".to_string(),
                app_id: 42,
                secret_key: "private-key.pem".to_string(),
                webhook_target: None,
                webhook_validation_secret_file: None,
                allowed_roles: Vec::new(),
            }],
            vec![workflow_self_scoping_policy()],
        );
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("evilorg/alfa");
        let github_app = state.github_app("default").unwrap().clone();
        let error = state
            .authorize_github_app(&github_app, "evilorg/alfa", Some(&token))
            .unwrap_err();
        assert!(matches!(error, AppError::Unauthorized(_)));
    }
}

/// The pilot's human token path: one exact repository, one exact Teleport role, no fallback.
///
/// Every token here is synthetic and signed with a key generated in-process. Nothing in this
/// module may be given a real Teleport token.
#[cfg(test)]
mod human_tests {
    use super::*;
    use crate::config::{HumanJwtAlgorithm, HumanPolicyConfig, HumanRoleConfig};
    use crate::human::HumanTokenValidator;
    use crate::secret::FilePrivateKeyStore;
    use crate::testkeys::{TeleportClaims, other_keys, test_keys};
    use serde_json::json;

    const ISSUER: &str = "https://teleport.example.invalid";
    const AUDIENCE: &str = "https://idcat.teleport.example.invalid:443";
    const TELEPORT_ROLE: &str = "github-app-token-pilot-repo";
    const HUMAN_ROLE: &str = "pilot-repo-reader";
    const APP: &str = "source-reader";
    const PILOT_REPO: &str = "myorg/pilot";
    const OTHER_REPO: &str = "myorg/other";
    const REQUEST_ID_CLAIM: &str = "teleport_request_id";

    fn human_role_config() -> HumanRoleConfig {
        HumanRoleConfig {
            name: HUMAN_ROLE.to_string(),
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            jwks_url: format!("{ISSUER}/.well-known/jwks.json"),
            teleport_role: TELEPORT_ROLE.to_string(),
            roles_claim: "roles".to_string(),
            algorithms: vec![HumanJwtAlgorithm::Rs256],
            request_id_claim: Some(REQUEST_ID_CLAIM.to_string()),
            required_claims: BTreeMap::new(),
        }
    }

    fn human_policy(repository: &str, permissions: &[(&str, &str)]) -> HumanPolicyConfig {
        HumanPolicyConfig {
            github_app: APP.to_string(),
            repository: repository.to_string(),
            human_role: HUMAN_ROLE.to_string(),
            permissions: permissions
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        }
    }

    fn github_app(allowed_roles: Vec<String>) -> GithubAppConfig {
        GithubAppConfig {
            name: APP.to_string(),
            app_id: 42,
            secret_key: "private-key.pem".to_string(),
            webhook_target: None,
            webhook_validation_secret_file: None,
            allowed_roles,
        }
    }

    /// Builds state whose human role validates against an in-process JWKS, so no test reaches the
    /// network.
    fn state(policies: Vec<HumanPolicyConfig>, app: GithubAppConfig) -> AppState {
        let config = human_role_config();
        let validator = HumanTokenValidator::from_static_jwks(
            &config.issuer,
            &config.audience,
            test_keys().jwks.clone(),
            vec![jsonwebtoken::Algorithm::RS256],
        );
        AppState {
            github_apps: Arc::new(vec![app]),
            installation_policies: Arc::new(Vec::new()),
            human_policies: Arc::new(policies),
            human_roles: Arc::new(BTreeMap::from([(
                HUMAN_ROLE.to_string(),
                HumanRole { config, validator },
            )])),
            token_validator: TokenValidator::new(Vec::new(), true).unwrap(),
            github: GithubClient::new().unwrap(),
            webhook_publisher: None,
            key_source: KeySource::Local,
            private_key_store: FilePrivateKeyStore::new("/var/run/secrets/idcat"),
            #[cfg(feature = "kms")]
            kms_signers: None,
        }
    }

    fn default_state() -> AppState {
        state(
            vec![human_policy(PILOT_REPO, &[("contents", "read")])],
            github_app(Vec::new()),
        )
    }

    fn claims(subject: &str) -> TeleportClaims {
        let mut claims = TeleportClaims::new(subject, ISSUER, AUDIENCE, json!([TELEPORT_ROLE]));
        claims.traits = None;
        claims
    }

    /// A Teleport token with a request id, matching what the Application Service issues after an
    /// approved access request.
    fn approved_token(subject: &str, request_id: &str) -> String {
        let claims = claims(subject);
        let mut value = serde_json::to_value(&claims).unwrap();
        value[REQUEST_ID_CLAIM] = json!(request_id);
        test_keys().sign(&value)
    }

    async fn authorize(
        state: &AppState,
        repo: &str,
        token: &str,
    ) -> Result<(TokenScope, HumanIdentity), AppError> {
        let app = state.github_app(APP).unwrap().clone();
        state.authorize_human(&app, repo, Some(token)).await
    }

    #[tokio::test]
    async fn exact_person_role_app_and_repository_is_authorized() {
        let state = default_state();
        let token = approved_token("alex.mason@example.invalid", "req-1");

        let (scope, identity) = authorize(&state, PILOT_REPO, &token).await.unwrap();

        assert_eq!(scope.repositories, RepoScope::OnlyRequested);
        assert_eq!(
            scope.permissions,
            BTreeMap::from([("contents".to_string(), "read".to_string())])
        );
        assert_eq!(identity.subject, "alex.mason@example.invalid");
        assert_eq!(identity.request_id.as_deref(), Some("req-1"));
        assert_eq!(identity.human_role, HUMAN_ROLE);
    }

    #[tokio::test]
    async fn right_person_and_role_but_wrong_repository_is_denied() {
        let state = default_state();
        let token = approved_token("alex.mason@example.invalid", "req-1");

        let error = authorize(&state, OTHER_REPO, &token).await.unwrap_err();

        // The policy lookup fails before the token is validated and long before GitHub is asked
        // for anything, so this denial costs no upstream call.
        assert!(
            matches!(&error, AppError::Unauthorized(message)
                if message.contains("no human-policy authorizes")),
            "expected an unauthorized policy-lookup failure, got {error:?}"
        );
    }

    #[tokio::test]
    async fn approval_for_one_repository_cannot_mint_for_a_renamed_repository() {
        let state = default_state();
        let token = approved_token("alex.mason@example.invalid", "req-1");

        assert!(
            authorize(&state, "myorg/pilot-renamed", &token)
                .await
                .is_err()
        );
        assert!(authorize(&state, "myorg/Pilot", &token).await.is_err());
        assert!(authorize(&state, "otherorg/pilot", &token).await.is_err());
    }

    #[tokio::test]
    async fn the_minted_scope_is_the_policy_permissions_not_the_installation() {
        let state = default_state();
        let token = approved_token("alex.mason@example.invalid", "req-1");

        let (scope, _) = authorize(&state, PILOT_REPO, &token).await.unwrap();

        assert_eq!(scope.repositories, RepoScope::OnlyRequested);
        assert!(
            !scope.permissions.contains_key("administration"),
            "a human token must carry only the permissions its policy names"
        );
        assert_eq!(scope.permissions.len(), 1);
    }

    #[tokio::test]
    async fn a_request_through_a_different_github_app_is_denied() {
        let other_app = GithubAppConfig {
            name: "another-app".to_string(),
            ..github_app(Vec::new())
        };
        let state = AppState {
            github_apps: Arc::new(vec![github_app(Vec::new()), other_app]),
            ..default_state()
        };
        let token = approved_token("alex.mason@example.invalid", "req-1");
        let app = state.github_app("another-app").unwrap().clone();

        assert!(
            state
                .authorize_human(&app, PILOT_REPO, Some(&token))
                .await
                .is_err(),
            "the policy names one App; another App installation must not satisfy it"
        );
    }

    #[tokio::test]
    async fn a_token_without_the_exact_teleport_role_is_denied() {
        let state = default_state();
        let mut raw = claims("alex.mason@example.invalid");
        raw.roles = json!(["some-other-role"]);
        let token = test_keys().sign(&raw);

        assert!(authorize(&state, PILOT_REPO, &token).await.is_err());
    }

    #[tokio::test]
    async fn a_wrong_audience_issuer_signature_or_expiry_is_denied() {
        let state = default_state();
        let cases: Vec<(&str, String)> = vec![
            ("wrong audience", {
                let mut raw = claims("a@example.invalid");
                raw.aud = "https://idcat.example.invalid".to_string();
                test_keys().sign(&raw)
            }),
            ("wrong issuer", {
                let mut raw = claims("a@example.invalid");
                raw.iss = "https://teleport.other.invalid".to_string();
                test_keys().sign(&raw)
            }),
            (
                "wrong signature",
                other_keys().sign(&claims("a@example.invalid")),
            ),
            ("expired", {
                let mut raw = claims("a@example.invalid");
                raw.exp = crate::testkeys::now() - 1;
                test_keys().sign(&raw)
            }),
        ];

        for (case, token) in cases {
            let error = authorize(&state, PILOT_REPO, &token).await.unwrap_err();
            assert!(
                matches!(error, AppError::Unauthorized(_)),
                "{case} must be refused outright, not retried against another path"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_authorization_header_is_denied() {
        let state = default_state();
        let app = state.github_app(APP).unwrap().clone();

        assert!(state.authorize_human(&app, PILOT_REPO, None).await.is_err());
    }

    #[tokio::test]
    async fn the_human_path_never_falls_back_to_allowed_roles() {
        // The App grants a workload role a broad token. A human request that fails its policy must
        // not be rescued by that path.
        let state = state(
            vec![human_policy(PILOT_REPO, &[("contents", "read")])],
            github_app(vec!["some-workload-role".to_string()]),
        );
        let mut raw = claims("alex.mason@example.invalid");
        raw.roles = json!(["not-the-pilot-role"]);
        let token = test_keys().sign(&raw);

        let error = authorize(&state, PILOT_REPO, &token).await.unwrap_err();

        assert!(matches!(error, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn a_wrong_repository_is_denied_even_when_the_app_has_broad_allowed_roles() {
        // The lookup-miss branch must not be rescued by `allowed-roles` either. Without this the
        // fail-closed property only holds for Apps that happen to have no workload roles.
        let state = state(
            vec![human_policy(PILOT_REPO, &[("contents", "read")])],
            github_app(vec!["some-workload-role".to_string()]),
        );
        let token = approved_token("alex.mason@example.invalid", "req-1");

        let error = authorize(&state, OTHER_REPO, &token).await.unwrap_err();

        assert!(
            matches!(&error, AppError::Unauthorized(message)
                if message.contains("no human-policy authorizes")),
            "expected a fail-closed denial, got {error:?}"
        );
    }

    #[tokio::test]
    async fn an_unknown_repository_is_denied_when_no_human_policy_exists_at_all() {
        let state = state(
            Vec::new(),
            github_app(vec!["some-workload-role".to_string()]),
        );
        let token = approved_token("alex.mason@example.invalid", "req-1");

        assert!(authorize(&state, PILOT_REPO, &token).await.is_err());
    }

    #[tokio::test]
    async fn a_workload_token_cannot_satisfy_a_human_policy() {
        let state = default_state();
        // A GitHub Actions style HS256 token, of the shape the workload path accepts.
        let workload_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &json!({
                "sub": "repo:myorg/pilot:ref:refs/heads/main",
                "aud": "idcat",
                "iss": "https://token.actions.githubusercontent.com",
                "exp": 4_102_444_800u64,
                "roles": [TELEPORT_ROLE],
            }),
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        assert!(
            authorize(&state, PILOT_REPO, &workload_token)
                .await
                .is_err(),
            "a workload token must not reach the human path even when it spells the right role"
        );
    }

    #[tokio::test]
    async fn a_human_token_cannot_satisfy_a_workload_policy() {
        let mut state = default_state();
        state.token_validator = TokenValidator::new(
            vec![authzoo::RoleConfig {
                name: "github-workflow".to_string(),
                audience: "idcat".to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                validation_key: Some("secret".to_string()),
                algorithms: vec![authzoo::JwtAlgorithm::Hs256],
                claims: BTreeMap::new(),
            }],
            false,
        )
        .unwrap();
        let app = GithubAppConfig {
            allowed_roles: vec!["github-workflow".to_string()],
            ..github_app(Vec::new())
        };
        let token = approved_token("alex.mason@example.invalid", "req-1");

        assert!(
            state
                .authorize_github_app(&app, PILOT_REPO, Some(&token))
                .is_err(),
            "a Teleport human token must not satisfy a workload allowed-role"
        );
    }

    #[tokio::test]
    async fn two_people_are_given_distinct_cache_partitions() {
        let state = default_state();
        let first = approved_token("first@example.invalid", "req-1");
        let second = approved_token("second@example.invalid", "req-2");

        let (_, first_identity) = authorize(&state, PILOT_REPO, &first).await.unwrap();
        let (_, second_identity) = authorize(&state, PILOT_REPO, &second).await.unwrap();

        assert_ne!(
            Requester::person(&first_identity),
            Requester::person(&second_identity),
            "two people must never share an installation-token cache entry"
        );
    }

    #[tokio::test]
    async fn a_second_approval_for_the_same_person_is_a_new_cache_partition() {
        let state = default_state();
        let first = approved_token("alex.mason@example.invalid", "req-1");
        let second = approved_token("alex.mason@example.invalid", "req-2");

        let (_, first_identity) = authorize(&state, PILOT_REPO, &first).await.unwrap();
        let (_, second_identity) = authorize(&state, PILOT_REPO, &second).await.unwrap();

        assert_ne!(
            Requester::person(&first_identity),
            Requester::person(&second_identity),
            "a fresh approval must not revive the token issued under the previous one"
        );
    }

    #[tokio::test]
    async fn a_person_is_never_served_the_shared_workload_partition() {
        let state = default_state();
        let token = approved_token("alex.mason@example.invalid", "req-1");

        let (_, identity) = authorize(&state, PILOT_REPO, &token).await.unwrap();

        assert_ne!(Requester::person(&identity), Requester::Workload);
    }
}
