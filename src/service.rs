// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::config::{
    Config, GithubAppConfig, InstallationPolicyConfig, KeySource, OwnerPolicyConfig,
    SELF_ACCESS_OWNER_CLAIM, WebhookTarget,
};
use crate::error::AppError;
use crate::github::GithubClient;
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
    pub owner_policies: Arc<Vec<OwnerPolicyConfig>>,
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
        owner_policies: Arc::new(config.owner_policies.clone()),
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

    /// Authorizes a request for an installation-wide token for `owner`, as served by
    /// `POST /installation-token/{github_app}/{owner}`. Unlike [`Self::authorize_github_app`] there
    /// is no requested repository, so only `[[owner-policy]]` entries (and app-level
    /// `allowed-roles`) can grant access.
    pub fn authorize_owner(
        &self,
        github_app: &GithubAppConfig,
        owner: &str,
        bearer_token: Option<&str>,
    ) -> Result<TokenScope, AppError> {
        if !self.token_validator.auth_enabled() {
            debug!(
                github_app = %github_app.name,
                owner = %owner,
                "skipping authorization because auth is disabled"
            );
            return Ok(TokenScope::broad());
        }
        let bearer_token = bearer_token
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
        let matching_roles = self.token_validator.validate(bearer_token);
        debug!(
            github_app = %github_app.name,
            owner = %owner,
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
        let owner_policy_match = self.owner_policies.iter().find(|owner_policy| {
            owner_policy.github_app == github_app.name
                && owner_policy
                    .owners
                    .iter()
                    .any(|pattern| wildmatch::WildMatch::new(pattern).matches(owner))
                && self.token_validator.validate_role_with_claims(
                    &owner_policy.role,
                    &claims_for_owner_request(owner_policy, owner),
                    bearer_token,
                )
        });
        if let Some(owner_policy) = owner_policy_match {
            return Ok(TokenScope {
                repositories: RepoScope::All,
                permissions: owner_policy.permissions.clone(),
            });
        }
        Err(AppError::Unauthorized(format!(
            "source token did not match any allowed role for github-app '{}' and owner '{}'",
            github_app.name, owner
        )))
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

fn claims_for_owner_request(
    owner_policy: &OwnerPolicyConfig,
    request_owner: &str,
) -> BTreeMap<String, authzoo::ClaimRequirement> {
    let mut claims = owner_policy.required_claims.clone();
    if owner_policy.allow_self_access {
        claims.insert(
            SELF_ACCESS_OWNER_CLAIM.to_string(),
            authzoo::ClaimRequirement::equals(request_owner),
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
    use crate::config::{GithubAppConfig, InstallationPolicyConfig, KeySource, OwnerPolicyConfig};
    use crate::error::AppError;
    use crate::github::GithubClient;
    use crate::secret::FilePrivateKeyStore;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_state(github_apps: Vec<GithubAppConfig>) -> AppState {
        test_state_with_policies(github_apps, Vec::new(), Vec::new())
    }

    fn test_state_with_installation_policies(
        github_apps: Vec<GithubAppConfig>,
        installation_policies: Vec<InstallationPolicyConfig>,
    ) -> AppState {
        test_state_with_policies(github_apps, installation_policies, Vec::new())
    }

    fn test_state_with_owner_policies(
        github_apps: Vec<GithubAppConfig>,
        owner_policies: Vec<OwnerPolicyConfig>,
    ) -> AppState {
        test_state_with_policies(github_apps, Vec::new(), owner_policies)
    }

    fn test_state_with_policies(
        github_apps: Vec<GithubAppConfig>,
        installation_policies: Vec<InstallationPolicyConfig>,
        owner_policies: Vec<OwnerPolicyConfig>,
    ) -> AppState {
        AppState {
            github_apps: Arc::new(github_apps),
            installation_policies: Arc::new(installation_policies),
            owner_policies: Arc::new(owner_policies),
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
        repository_owner: &'a str,
    }

    /// Mints a GitHub Actions-shaped token for `repository`, deriving `repository_owner` from it the
    /// way GitHub does.
    fn github_workflow_token(repository: &str) -> String {
        let repository_owner = repository
            .split_once('/')
            .map(|(owner, _)| owner)
            .unwrap_or(repository);
        encode(
            &Header::new(Algorithm::HS256),
            &TestClaims {
                sub: "repo:myorg/gamma:ref:refs/heads/main",
                aud: "idcat",
                iss: "https://token.actions.githubusercontent.com",
                exp: 4_102_444_800,
                repository,
                repository_owner,
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

    fn default_github_app() -> GithubAppConfig {
        GithubAppConfig {
            name: "default".to_string(),
            app_id: 42,
            secret_key: "private-key.pem".to_string(),
            webhook_target: None,
            webhook_validation_secret_file: None,
            allowed_roles: Vec::new(),
        }
    }

    fn packages_owner_policy() -> OwnerPolicyConfig {
        OwnerPolicyConfig {
            github_app: "default".to_string(),
            owners: vec!["myorg".to_string()],
            role: "github-workflow".to_string(),
            required_claims: BTreeMap::new(),
            allow_self_access: true,
            permissions: [("packages".to_string(), "read".to_string())]
                .into_iter()
                .collect(),
        }
    }

    fn state_with_owner_policy(owner_policy: OwnerPolicyConfig) -> AppState {
        let mut state =
            test_state_with_owner_policies(vec![default_github_app()], vec![owner_policy]);
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();
        state
    }

    #[test]
    fn authorize_owner_returns_all_repos_with_the_policy_permissions() {
        let state = state_with_owner_policy(packages_owner_policy());

        let token = github_workflow_token("myorg/alfa");
        let github_app = state.github_app("default").unwrap().clone();
        let scope = state
            .authorize_owner(&github_app, "myorg", Some(&token))
            .unwrap();

        assert_eq!(scope.repositories, RepoScope::All);
        assert_eq!(
            scope.permissions.get("packages").map(String::as_str),
            Some("read")
        );
    }

    #[test]
    fn authorize_owner_rejects_a_workflow_from_another_owner_when_self_access_is_set() {
        let mut owner_policy = packages_owner_policy();
        owner_policy.owners = vec!["*".to_string()];
        let state = state_with_owner_policy(owner_policy);

        // The workflow belongs to `otherorg`, so `allow-self-access` must not let it mint a token
        // covering `myorg`'s installation.
        let token = github_workflow_token("otherorg/alfa");
        let github_app = state.github_app("default").unwrap().clone();
        let error = state
            .authorize_owner(&github_app, "myorg", Some(&token))
            .unwrap_err();

        assert!(matches!(error, AppError::Unauthorized(_)));
    }

    #[test]
    fn authorize_owner_rejects_an_owner_outside_the_policy() {
        let state = state_with_owner_policy(packages_owner_policy());

        let token = github_workflow_token("otherorg/alfa");
        let github_app = state.github_app("default").unwrap().clone();
        let error = state
            .authorize_owner(&github_app, "otherorg", Some(&token))
            .unwrap_err();

        assert!(matches!(error, AppError::Unauthorized(_)));
    }

    #[test]
    fn authorize_owner_ignores_installation_policies() {
        // An installation-policy grants repository-scoped tokens only. It must not be reusable as a
        // grant for the owner endpoint, which hands out installation-wide tokens.
        let mut state = test_state_with_installation_policies(
            vec![default_github_app()],
            vec![workflow_self_scoping_policy()],
        );
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("myorg/alfa");
        let github_app = state.github_app("default").unwrap().clone();
        let error = state
            .authorize_owner(&github_app, "myorg", Some(&token))
            .unwrap_err();

        assert!(matches!(error, AppError::Unauthorized(_)));
    }

    #[test]
    fn authorize_owner_requires_bearer_token_when_auth_enabled() {
        let state = state_with_owner_policy(packages_owner_policy());

        let github_app = state.github_app("default").unwrap().clone();
        let error = state
            .authorize_owner(&github_app, "myorg", None)
            .unwrap_err();

        assert!(matches!(error, AppError::Unauthorized(_)));
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
