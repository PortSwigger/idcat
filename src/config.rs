// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use anyhow::Context;
use serde::{Deserialize, Deserializer, de};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;
use tracing::warn;

#[derive(Debug, Deserialize)]
struct KnownPermissionsFile {
    #[serde(default)]
    permissions: Vec<String>,
}

static KNOWN_GITHUB_PERMISSIONS: LazyLock<HashSet<String>> = LazyLock::new(|| {
    let file: KnownPermissionsFile = toml::from_str(include_str!("github-permissions.toml"))
        .expect("embedded github-permissions.toml must be valid TOML");
    file.permissions.into_iter().collect()
});

const KNOWN_PERMISSION_VALUES: [&str; 3] = ["read", "write", "admin"];

/// The claim an `owner-policy` with `allow-self-access` constrains to the requested owner. GitHub
/// Actions OIDC tokens carry the account that owns the workflow's repository in `repository_owner`.
pub const SELF_ACCESS_OWNER_CLAIM: &str = "repository_owner";

fn known_github_permissions() -> &'static HashSet<String> {
    &KNOWN_GITHUB_PERMISSIONS
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub key_source: KeySource,
    #[serde(default = "default_private_key_directory")]
    pub private_key_directory: String,
    pub nats: Option<NatsConfig>,
    #[serde(rename = "role", default)]
    pub roles: Vec<authzoo::RoleConfig>,
    #[serde(rename = "github-app", default)]
    pub github_apps: Vec<GithubAppConfig>,
    #[serde(rename = "installation-policy", default)]
    pub installation_policies: Vec<InstallationPolicyConfig>,
    #[serde(rename = "owner-policy", default)]
    pub owner_policies: Vec<OwnerPolicyConfig>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct TlsConfig {
    pub certificate_file: String,
    pub private_key_file: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum KeySource {
    #[default]
    Local,
    Kms,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum WebhookTarget {
    Nats,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct NatsConfig {
    pub endpoint: String,
    pub subject_base: String,
    pub token_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GithubAppConfig {
    pub name: String,
    pub app_id: u64,
    pub secret_key: String,
    pub webhook_target: Option<WebhookTarget>,
    pub webhook_validation_secret_file: Option<String>,
    #[serde(default)]
    pub allowed_roles: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InstallationPolicyConfig {
    pub github_app: String,
    pub repositories: Vec<String>,
    pub role: String,
    pub required_claims: BTreeMap<String, authzoo::ClaimRequirement>,
    pub allow_self_access: bool,
    pub permissions: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawInstallationPolicyConfig {
    github_app: String,
    repository: Option<String>,
    repositories: Option<Vec<String>>,
    role: String,
    #[serde(rename = "required-claims", default)]
    required_claims: BTreeMap<String, authzoo::ClaimRequirement>,
    #[serde(default)]
    allow_self_access: bool,
    // Keys are GitHub permission names (snake_case), not kebab-case.
    #[serde(default)]
    permissions: BTreeMap<String, String>,
}

impl<'de> Deserialize<'de> for InstallationPolicyConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawInstallationPolicyConfig::deserialize(deserializer)?;
        let repositories = match (raw.repository, raw.repositories) {
            (Some(_), Some(_)) => {
                return Err(de::Error::custom(
                    "installation-policy must specify either repository or repositories, not both",
                ));
            }
            (Some(repository), None) => vec![repository],
            (None, Some(repositories)) => repositories,
            (None, None) => {
                return Err(de::Error::custom(
                    "installation-policy must specify either repository or repositories",
                ));
            }
        };

        Ok(Self {
            github_app: raw.github_app,
            repositories,
            role: raw.role,
            required_claims: raw.required_claims,
            allow_self_access: raw.allow_self_access,
            permissions: raw.permissions,
        })
    }
}

impl InstallationPolicyConfig {
    pub fn repositories_label(&self) -> String {
        self.repositories.join(", ")
    }
}

/// Grants a role an installation-wide token for an account (organization or user), rather than a
/// token scoped to a single repository. Served by `POST /installation-token/{github_app}/{owner}`,
/// which names no repository, so the minted token's scope matches the request path. Intended for
/// account-level resources (e.g. org-owned packages) that a single-repository token cannot read.
#[derive(Debug, Clone)]
pub struct OwnerPolicyConfig {
    pub github_app: String,
    pub owners: Vec<String>,
    pub role: String,
    pub required_claims: BTreeMap<String, authzoo::ClaimRequirement>,
    pub allow_self_access: bool,
    pub permissions: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawOwnerPolicyConfig {
    github_app: String,
    owner: Option<String>,
    owners: Option<Vec<String>>,
    role: String,
    #[serde(rename = "required-claims", default)]
    required_claims: BTreeMap<String, authzoo::ClaimRequirement>,
    #[serde(default)]
    allow_self_access: bool,
    // Keys are GitHub permission names (snake_case), not kebab-case.
    #[serde(default)]
    permissions: BTreeMap<String, String>,
}

impl<'de> Deserialize<'de> for OwnerPolicyConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawOwnerPolicyConfig::deserialize(deserializer)?;
        let owners = match (raw.owner, raw.owners) {
            (Some(_), Some(_)) => {
                return Err(de::Error::custom(
                    "owner-policy must specify either owner or owners, not both",
                ));
            }
            (Some(owner), None) => vec![owner],
            (None, Some(owners)) => owners,
            (None, None) => {
                return Err(de::Error::custom(
                    "owner-policy must specify either owner or owners",
                ));
            }
        };

        Ok(Self {
            github_app: raw.github_app,
            owners,
            role: raw.role,
            required_claims: raw.required_claims,
            allow_self_access: raw.allow_self_access,
            permissions: raw.permissions,
        })
    }
}

impl OwnerPolicyConfig {
    pub fn owners_label(&self) -> String {
        self.owners.join(", ")
    }
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Could not read config file '{path}'"))?;
        toml::from_str(&content)
            .map_err(|error| anyhow::anyhow!("Could not parse config file '{path}': {error}"))
    }

    pub fn validate(&self, disable_auth: bool) -> anyhow::Result<()> {
        if self.bind_address.is_empty() {
            anyhow::bail!("bind-address must not be empty");
        }
        if let Some(tls) = &self.tls {
            if tls.certificate_file.is_empty() {
                anyhow::bail!("tls certificate-file must not be empty");
            }
            if tls.private_key_file.is_empty() {
                anyhow::bail!("tls private-key-file must not be empty");
            }
        }
        if self.key_source == KeySource::Local && self.private_key_directory.is_empty() {
            anyhow::bail!("private-key-directory must not be empty");
        }
        if self.key_source == KeySource::Kms && !cfg!(feature = "kms") {
            anyhow::bail!("key-source 'kms' requires idcat to be built with the 'kms' feature");
        }
        let any_nats_webhook_target = self
            .github_apps
            .iter()
            .any(|github_app| matches!(github_app.webhook_target, Some(WebhookTarget::Nats)));
        if any_nats_webhook_target && self.nats.is_none() {
            anyhow::bail!("webhook-target 'nats' requires a [nats] config block");
        }
        if let Some(nats) = &self.nats {
            if nats.endpoint.is_empty() {
                anyhow::bail!("nats endpoint must not be empty");
            }
            if nats.subject_base.is_empty() {
                anyhow::bail!("nats subject-base must not be empty");
            }
            if nats.subject_base.chars().any(char::is_whitespace) {
                anyhow::bail!("nats subject-base must not contain whitespace");
            }
            if matches!(nats.token_path.as_deref(), Some("")) {
                anyhow::bail!("nats token-path must not be empty when set");
            }
            if !any_nats_webhook_target {
                warn!(
                    "nats config is present but no github-app sets webhook-target = \"nats\"; nats will not be used"
                );
            }
        }
        let role_validator = authzoo::TokenValidator::new(self.roles.clone())?;
        if !disable_auth && self.roles.is_empty() {
            anyhow::bail!("at least one [[role]] entry is required");
        }

        if self.github_apps.is_empty() {
            anyhow::bail!("at least one [[github-app]] entry is required");
        }
        let mut github_apps = std::collections::HashSet::new();
        for github_app in &self.github_apps {
            if github_app.name.is_empty() {
                anyhow::bail!("github-app names must not be empty");
            }
            if github_app.name.contains('/') {
                anyhow::bail!("github-app '{}' name must not contain '/'", github_app.name);
            }
            if github_app.app_id == 0 {
                anyhow::bail!(
                    "github-app '{}' app-id must be greater than 0",
                    github_app.name
                );
            }
            if github_app.secret_key.is_empty() {
                anyhow::bail!("github-app '{}' must define secret-key", github_app.name);
            }
            if self.key_source == KeySource::Local
                && (Path::new(&github_app.secret_key).is_absolute()
                    || github_app.secret_key.contains(".."))
            {
                anyhow::bail!(
                    "github-app '{}' secret-key must be a relative file name",
                    github_app.name
                );
            }
            if matches!(
                github_app.webhook_validation_secret_file.as_deref(),
                Some("")
            ) {
                anyhow::bail!(
                    "github-app '{}' webhook-validation-secret-file must not be empty when set",
                    github_app.name
                );
            }
            if !github_apps.insert(github_app.name.clone()) {
                anyhow::bail!("duplicate github-app '{}'", github_app.name);
            }
            if !disable_auth {
                for role in &github_app.allowed_roles {
                    if role.is_empty() {
                        anyhow::bail!(
                            "github-app '{}' allowed-roles must not contain empty entries",
                            github_app.name
                        );
                    }
                }
                role_validator
                    .ensure_roles_exist(github_app.allowed_roles.iter().map(String::as_str))?;
            }
        }
        if !disable_auth {
            for installation_policy in &self.installation_policies {
                if installation_policy.github_app.is_empty() {
                    anyhow::bail!("installation-policy github-app must not be empty");
                }
                if !github_apps.contains(&installation_policy.github_app) {
                    anyhow::bail!(
                        "installation-policy references unknown github-app '{}'",
                        installation_policy.github_app
                    );
                }
                if installation_policy.repositories.is_empty() {
                    anyhow::bail!(
                        "installation-policy for github-app '{}' must define at least one repository",
                        installation_policy.github_app
                    );
                }
                for repository in &installation_policy.repositories {
                    if !is_valid_repo_pattern(repository) {
                        anyhow::bail!(
                            "installation-policy for github-app '{}' must define repository as owner/name or a glob like 'owner/*' or '*'",
                            installation_policy.github_app
                        );
                    }
                }
                if installation_policy.role.is_empty() {
                    anyhow::bail!(
                        "installation-policy for github-app '{}' repository '{}' must define role",
                        installation_policy.github_app,
                        installation_policy.repositories_label()
                    );
                }
                role_validator.ensure_roles_exist([installation_policy.role.as_str()])?;
                if installation_policy.required_claims.is_empty()
                    && !installation_policy.allow_self_access
                {
                    anyhow::bail!(
                        "installation-policy for github-app '{}' repository '{}' role '{}' must define at least one required-claim (or set allow-self-access)",
                        installation_policy.github_app,
                        installation_policy.repositories_label(),
                        installation_policy.role
                    );
                }
                let role_claims = &role_validator.roles()[&installation_policy.role].claims;
                for (claim, requirement) in &installation_policy.required_claims {
                    if claim.is_empty() {
                        anyhow::bail!(
                            "installation-policy for github-app '{}' repository '{}' role '{}' required-claim names must not be empty",
                            installation_policy.github_app,
                            installation_policy.repositories_label(),
                            installation_policy.role
                        );
                    }
                    requirement.validate(&installation_policy.role, claim)?;
                    if role_claims.contains_key(claim) {
                        anyhow::bail!(
                            "installation-policy for github-app '{}' repository '{}' role '{}' required-claim '{}' duplicates a role claim",
                            installation_policy.github_app,
                            installation_policy.repositories_label(),
                            installation_policy.role,
                            claim
                        );
                    }
                }
                if installation_policy.allow_self_access {
                    if installation_policy
                        .required_claims
                        .contains_key("repository")
                    {
                        anyhow::bail!(
                            "installation-policy for github-app '{}' repository '{}' role '{}' sets allow-self-access; required-claims must not also define 'repository' (allow-self-access already constrains it to the requested repo)",
                            installation_policy.github_app,
                            installation_policy.repositories_label(),
                            installation_policy.role
                        );
                    }
                    if role_claims.contains_key("repository") {
                        anyhow::bail!(
                            "installation-policy for github-app '{}' repository '{}' role '{}' sets allow-self-access, but role '{}' already constrains the 'repository' claim",
                            installation_policy.github_app,
                            installation_policy.repositories_label(),
                            installation_policy.role,
                            installation_policy.role
                        );
                    }
                }
                for (name, value) in &installation_policy.permissions {
                    if !known_github_permissions().contains(name.as_str()) {
                        warn!(
                            github_app = %installation_policy.github_app,
                            repository = %installation_policy.repositories_label(),
                            role = %installation_policy.role,
                            permission = %name,
                            "permission '{name}' is not a recognised GitHub permission. If this is intended, consider updating the permissions list."
                        );
                    }
                    if !KNOWN_PERMISSION_VALUES.contains(&value.as_str()) {
                        warn!(
                            github_app = %installation_policy.github_app,
                            repository = %installation_policy.repositories_label(),
                            role = %installation_policy.role,
                            permission = %name,
                            value = %value,
                            "'{value}' is not a recognised access level (expected read, write or admin) for permission '{name}'. If this is intended, it will still be forwarded to GitHub."
                        );
                    }
                }
            }
            for owner_policy in &self.owner_policies {
                if owner_policy.github_app.is_empty() {
                    anyhow::bail!("owner-policy github-app must not be empty");
                }
                if !github_apps.contains(&owner_policy.github_app) {
                    anyhow::bail!(
                        "owner-policy references unknown github-app '{}'",
                        owner_policy.github_app
                    );
                }
                if owner_policy.owners.is_empty() {
                    anyhow::bail!(
                        "owner-policy for github-app '{}' must define at least one owner",
                        owner_policy.github_app
                    );
                }
                for owner in &owner_policy.owners {
                    if !is_valid_owner_pattern(owner) {
                        anyhow::bail!(
                            "owner-policy for github-app '{}' must define owner as an account name or a glob like 'myorg-*' or '*', without a '/'",
                            owner_policy.github_app
                        );
                    }
                }
                if owner_policy.role.is_empty() {
                    anyhow::bail!(
                        "owner-policy for github-app '{}' owner '{}' must define role",
                        owner_policy.github_app,
                        owner_policy.owners_label()
                    );
                }
                role_validator.ensure_roles_exist([owner_policy.role.as_str()])?;
                // An owner-policy token reaches every repository the installation can access, so
                // `permissions` is the only thing keeping it narrower than an allowed-role token.
                // Require it, rather than silently minting the broadest token GitHub will issue.
                if owner_policy.permissions.is_empty() {
                    anyhow::bail!(
                        "owner-policy for github-app '{}' owner '{}' role '{}' must define at least one permission under [owner-policy.permissions]; an owner-wide token without narrowed permissions is what allowed-roles already grants",
                        owner_policy.github_app,
                        owner_policy.owners_label(),
                        owner_policy.role
                    );
                }
                if owner_policy.required_claims.is_empty() && !owner_policy.allow_self_access {
                    anyhow::bail!(
                        "owner-policy for github-app '{}' owner '{}' role '{}' must define at least one required-claim (or set allow-self-access)",
                        owner_policy.github_app,
                        owner_policy.owners_label(),
                        owner_policy.role
                    );
                }
                let role_claims = &role_validator.roles()[&owner_policy.role].claims;
                for (claim, requirement) in &owner_policy.required_claims {
                    if claim.is_empty() {
                        anyhow::bail!(
                            "owner-policy for github-app '{}' owner '{}' role '{}' required-claim names must not be empty",
                            owner_policy.github_app,
                            owner_policy.owners_label(),
                            owner_policy.role
                        );
                    }
                    requirement.validate(&owner_policy.role, claim)?;
                    if role_claims.contains_key(claim) {
                        anyhow::bail!(
                            "owner-policy for github-app '{}' owner '{}' role '{}' required-claim '{}' duplicates a role claim",
                            owner_policy.github_app,
                            owner_policy.owners_label(),
                            owner_policy.role,
                            claim
                        );
                    }
                }
                if owner_policy.allow_self_access {
                    if owner_policy
                        .required_claims
                        .contains_key(SELF_ACCESS_OWNER_CLAIM)
                    {
                        anyhow::bail!(
                            "owner-policy for github-app '{}' owner '{}' role '{}' sets allow-self-access; required-claims must not also define '{SELF_ACCESS_OWNER_CLAIM}' (allow-self-access already constrains it to the requested owner)",
                            owner_policy.github_app,
                            owner_policy.owners_label(),
                            owner_policy.role
                        );
                    }
                    if role_claims.contains_key(SELF_ACCESS_OWNER_CLAIM) {
                        anyhow::bail!(
                            "owner-policy for github-app '{}' owner '{}' role '{}' sets allow-self-access, but role '{}' already constrains the '{SELF_ACCESS_OWNER_CLAIM}' claim",
                            owner_policy.github_app,
                            owner_policy.owners_label(),
                            owner_policy.role,
                            owner_policy.role
                        );
                    }
                }
                for (name, value) in &owner_policy.permissions {
                    if !known_github_permissions().contains(name.as_str()) {
                        warn!(
                            github_app = %owner_policy.github_app,
                            owner = %owner_policy.owners_label(),
                            role = %owner_policy.role,
                            permission = %name,
                            "permission '{name}' is not a recognised GitHub permission. If this is intended, consider updating the permissions list."
                        );
                    }
                    if !KNOWN_PERMISSION_VALUES.contains(&value.as_str()) {
                        warn!(
                            github_app = %owner_policy.github_app,
                            owner = %owner_policy.owners_label(),
                            role = %owner_policy.role,
                            permission = %name,
                            value = %value,
                            "'{value}' is not a recognised access level (expected read, write or admin) for permission '{name}'. If this is intended, it will still be forwarded to GitHub."
                        );
                    }
                }
            }
            for github_app in &self.github_apps {
                let has_installation_policy = self
                    .installation_policies
                    .iter()
                    .any(|installation_policy| installation_policy.github_app == github_app.name);
                let has_owner_policy = self
                    .owner_policies
                    .iter()
                    .any(|owner_policy| owner_policy.github_app == github_app.name);
                if github_app.allowed_roles.is_empty()
                    && !has_installation_policy
                    && !has_owner_policy
                {
                    anyhow::bail!(
                        "github-app '{}' must define at least one allowed-role, installation-policy or owner-policy",
                        github_app.name
                    );
                }
            }
        }
        Ok(())
    }
}

fn is_valid_owner_pattern(pattern: &str) -> bool {
    !pattern.is_empty() && !pattern.contains('/')
}

fn is_valid_repo_pattern(pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    let Some((owner, name)) = pattern.split_once('/') else {
        return false;
    };
    if name.contains('/') {
        return false;
    }
    !owner.is_empty() && !name.is_empty()
}

fn default_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_private_key_directory() -> String {
    "/var/run/secrets/idcat".to_string()
}

#[cfg(test)]
mod tests {
    use super::{Config, KeySource, WebhookTarget};

    #[test]
    fn accepts_wildcard_repository_without_allow_self_access() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/*"
role = "github-workflow"

[installation-policy.required-claims]
environment = "production"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
    }

    #[test]
    fn accepts_wildcard_repository_with_allow_self_access() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/*"
role = "github-workflow"
allow-self-access = true
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
    }

    #[test]
    fn accepts_bare_star_wildcard_with_allow_self_access() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "*"
role = "github-workflow"
allow-self-access = true
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
    }

    #[test]
    fn parses_installation_policy_with_allow_self_access() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/alfa"
role = "github-workflow"
allow-self-access = true
"#,
        )
        .unwrap();

        let policy = &config.installation_policies[0];
        assert_eq!(policy.repositories, vec!["myorg/alfa".to_string()]);
        assert!(policy.allow_self_access);
        assert!(policy.required_claims.is_empty());
    }

    #[test]
    fn parses_installation_policy_with_repositories() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repositories = ["myorg/alfa", "myorg/bravo"]
role = "github-workflow"

[installation-policy.required-claims]
repository = "myorg/gamma"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
        assert_eq!(
            config.installation_policies[0].repositories,
            vec!["myorg/alfa".to_string(), "myorg/bravo".to_string()]
        );
    }

    #[test]
    fn rejects_installation_policy_with_both_repository_forms() {
        let error = toml::from_str::<Config>(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/alfa"
repositories = ["myorg/bravo"]
role = "github-workflow"

[installation-policy.required-claims]
repository = "myorg/gamma"
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("either repository or repositories, not both"),
            "expected repository/repositories conflict error, got: {error}"
        );
    }

    #[test]
    fn rejects_installation_policy_without_repository_form() {
        let error = toml::from_str::<Config>(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
role = "github-workflow"

[installation-policy.required-claims]
repository = "myorg/gamma"
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("either repository or repositories"),
            "expected missing repository/repositories error, got: {error}"
        );
    }

    #[test]
    fn rejects_installation_policy_with_empty_repositories() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repositories = []
role = "github-workflow"

[installation-policy.required-claims]
repository = "myorg/gamma"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err().to_string();
        assert!(
            error.contains("at least one repository"),
            "expected empty repositories error, got: {error}"
        );
    }

    #[test]
    fn rejects_allow_self_access_with_explicit_repository_required_claim() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/*"
role = "github-workflow"
allow-self-access = true

[installation-policy.required-claims]
repository = "myorg/alfa"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err().to_string();
        assert!(
            error.contains("allow-self-access"),
            "expected allow-self-access conflict error, got: {error}"
        );
    }

    #[test]
    fn required_claims_accepts_any_of_list_form() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/alfa"
role = "github-workflow"

[installation-policy.required-claims]
repository = ["myorg/alfa", "myorg/bravo"]
"#,
        )
        .unwrap();

        config.validate(false).unwrap();

        let policy = &config.installation_policies[0];
        match policy.required_claims.get("repository") {
            Some(authzoo::ClaimRequirement::AnyOf(values)) => {
                assert_eq!(
                    values,
                    &vec!["myorg/alfa".to_string(), "myorg/bravo".to_string()]
                );
            }
            other => panic!("expected ClaimRequirement::AnyOf([..]), got {other:?}"),
        }
    }

    #[test]
    fn rejects_installation_policy_with_malformed_repository_pattern() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "owner-only-no-slash"
role = "github-workflow"

[installation-policy.required-claims]
repository = "myorg/gamma"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err().to_string();
        assert!(
            error.contains("owner/name"),
            "expected owner/name error, got: {error}"
        );
    }

    #[test]
    fn known_github_permissions_parses_data_file_ignoring_comments_and_blanks() {
        let perms = super::known_github_permissions();
        assert!(perms.contains("contents"), "expected repo-level 'contents'");
        assert!(
            perms.contains("pull_requests"),
            "expected repo-level 'pull_requests'"
        );
        assert!(
            perms.contains("organization_administration"),
            "expected org-level permission"
        );
        assert!(
            !perms.contains("definitely_not_a_real_permission"),
            "made-up permission must be absent"
        );
        assert!(
            !perms.iter().any(|p| p.is_empty() || p.starts_with('#')),
            "comments and blank lines must not become entries"
        );
    }

    #[test]
    fn validate_accepts_unknown_permission_name_and_value_without_error() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/alfa"
role = "github-workflow"

[installation-policy.required-claims]
repository = "myorg/gamma"

[installation-policy.permissions]
made_up_permission = "sideways"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
    }

    #[test]
    fn parses_installation_policy_with_permissions() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/*"
role = "github-workflow"

[installation-policy.required-claims]
repository = "myorg/gamma"

[installation-policy.permissions]
contents = "read"
pull_requests = "write"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
        let policy = &config.installation_policies[0];
        assert_eq!(
            policy.permissions.get("contents").map(String::as_str),
            Some("read")
        );
        assert_eq!(
            policy.permissions.get("pull_requests").map(String::as_str),
            Some("write")
        );
    }

    #[test]
    fn installation_policy_permissions_default_empty_when_absent() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/alfa"
role = "github-workflow"

[installation-policy.required-claims]
repository = "myorg/gamma"
"#,
        )
        .unwrap();

        let policy = &config.installation_policies[0];
        assert!(policy.permissions.is_empty());
    }

    #[test]
    fn parses_minimal_config() {
        let config: Config = toml::from_str(
            r#"
[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
allowed-roles = ["kubernetes-default"]

[[role]]
name = "kubernetes-default"
audience = "idcat"
issuer = "https://kubernetes.default.svc"
validation-key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwFi8U2NAcihFpXAvLmOz
K1GfRjFzTuGWVDEBjjyEjSiDeBFZEl+gq3TnDFw9+TQPPbjLbFou5HIZ11PoT+sp
d26cU1FsvNEJMzlr4esgzdd9bR7lMcz/Y3CkSga1fQupgp85VpKfE0X7oUVDQYQq
vyuxfmcMdoBLwBXU9nWXL8Y6QaHCUuekpYLgiQf+mBqh1n3LJqllCL/73zIcGmk+
Kbh2b10d0fDtaUzw7mfbFW7S34v2wAs8SjsUPq6OhtTnmhUR1sZQ2AAJWQdm+lVr
S0kRuvb81yBZzXrfzskMnNL2PQ7aZuO0D3XHNgzTtze6+jJdgAm2UeSA4QIDAQAB
-----END PUBLIC KEY-----
"""

[role.claims]
sub = "system:serviceaccount:idelephant:default"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.tls, None);
        assert_eq!(config.key_source, KeySource::Local);
        assert_eq!(config.private_key_directory, "/var/run/secrets/idcat");
        assert_eq!(config.github_apps[0].webhook_target, None);
        assert_eq!(config.nats, None);
    }

    #[test]
    fn parses_tls_config() {
        let config: Config = toml::from_str(
            r#"
[tls]
certificate-file = "/var/run/secrets/idcat/tls.crt"
private-key-file = "/var/run/secrets/idcat/tls.key"

[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        let tls = config.tls.unwrap();
        assert_eq!(tls.certificate_file, "/var/run/secrets/idcat/tls.crt");
        assert_eq!(tls.private_key_file, "/var/run/secrets/idcat/tls.key");
    }

    #[test]
    fn rejects_empty_tls_file_paths() {
        for (certificate_file, private_key_file, expected_error) in [
            (
                "",
                "/var/run/secrets/idcat/tls.key",
                "tls certificate-file must not be empty",
            ),
            (
                "/var/run/secrets/idcat/tls.crt",
                "",
                "tls private-key-file must not be empty",
            ),
        ] {
            let config: Config = toml::from_str(&format!(
                r#"
[tls]
certificate-file = "{certificate_file}"
private-key-file = "{private_key_file}"

[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
"#,
            ))
            .unwrap();

            let error = config.validate(true).unwrap_err().to_string();
            assert_eq!(error, expected_error);
        }
    }

    #[test]
    fn parses_nats_webhook_target_config() {
        let config: Config = toml::from_str(
            r#"
[nats]
endpoint = "nats://nats.example.com:4222"
subject-base = "idcat.github.webhook"
token-path = "/var/run/secrets/idcat/nats-token"

[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
webhook-target = "nats"
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert_eq!(
            config.github_apps[0].webhook_target,
            Some(WebhookTarget::Nats)
        );
        let nats = config.nats.as_ref().unwrap();
        assert_eq!(nats.endpoint, "nats://nats.example.com:4222");
        assert_eq!(nats.subject_base, "idcat.github.webhook");
        assert_eq!(
            nats.token_path.as_deref(),
            Some("/var/run/secrets/idcat/nats-token")
        );
    }

    #[test]
    fn rejects_nats_webhook_target_without_nats_config() {
        let config: Config = toml::from_str(
            r#"
[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
webhook-target = "nats"
"#,
        )
        .unwrap();

        let error = config.validate(true).unwrap_err().to_string();
        assert_eq!(
            error,
            "webhook-target 'nats' requires a [nats] config block"
        );
    }

    #[test]
    fn rejects_empty_nats_token_path() {
        let config: Config = toml::from_str(
            r#"
[nats]
endpoint = "nats://nats.example.com:4222"
subject-base = "idcat.github.webhook"
token-path = ""

[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
webhook-target = "nats"
"#,
        )
        .unwrap();

        let error = config.validate(true).unwrap_err().to_string();
        assert_eq!(error, "nats token-path must not be empty when set");
    }

    #[test]
    fn parses_webhook_validation_secret_file() {
        let config: Config = toml::from_str(
            r#"
[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
webhook-validation-secret-file = "/var/run/secrets/idcat/webhook-secret"
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert_eq!(
            config.github_apps[0]
                .webhook_validation_secret_file
                .as_deref(),
            Some("/var/run/secrets/idcat/webhook-secret")
        );
    }

    #[test]
    fn rejects_empty_webhook_validation_secret_file() {
        let config: Config = toml::from_str(
            r#"
[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
webhook-validation-secret-file = ""
"#,
        )
        .unwrap();

        let error = config.validate(true).unwrap_err().to_string();
        assert_eq!(
            error,
            "github-app 'default' webhook-validation-secret-file must not be empty when set"
        );
    }

    #[test]
    #[cfg(feature = "kms")]
    fn accepts_kms_key_source_when_kms_feature_is_enabled() {
        let config: Config = toml::from_str(
            r#"
key-source = "kms"

[[github-app]]
name = "default"
app-id = 42
secret-key = "default"
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert_eq!(config.key_source, KeySource::Kms);
    }

    #[test]
    #[cfg(not(feature = "kms"))]
    fn rejects_kms_key_source_when_kms_feature_is_disabled() {
        let config: Config = toml::from_str(
            r#"
key-source = "kms"

[[github-app]]
name = "default"
app-id = 42
secret-key = "default"
"#,
        )
        .unwrap();

        let error = config.validate(true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "key-source 'kms' requires idcat to be built with the 'kms' feature"
        );
    }

    #[test]
    fn accepts_multiple_allowed_roles_for_github_app() {
        let config: Config = toml::from_str(
            r#"
[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
allowed-roles = ["kubernetes-default", "buildkite-deploy"]

[[role]]
name = "kubernetes-default"
audience = "idcat"
issuer = "https://kubernetes.default.svc"
validation-key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwFi8U2NAcihFpXAvLmOz
K1GfRjFzTuGWVDEBjjyEjSiDeBFZEl+gq3TnDFw9+TQPPbjLbFou5HIZ11PoT+sp
d26cU1FsvNEJMzlr4esgzdd9bR7lMcz/Y3CkSga1fQupgp85VpKfE0X7oUVDQYQq
vyuxfmcMdoBLwBXU9nWXL8Y6QaHCUuekpYLgiQf+mBqh1n3LJqllCL/73zIcGmk+
Kbh2b10d0fDtaUzw7mfbFW7S34v2wAs8SjsUPq6OhtTnmhUR1sZQ2AAJWQdm+lVr
S0kRuvb81yBZzXrfzskMnNL2PQ7aZuO0D3XHNgzTtze6+jJdgAm2UeSA4QIDAQAB
-----END PUBLIC KEY-----
"""

[[role]]
name = "buildkite-deploy"
audience = "idcat"
issuer = "https://agent.buildkite.com"
validation-key = "shared-secret"
algorithms = ["HS256"]
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
    }

    #[test]
    fn accepts_installation_policy_with_required_claims() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/alfa"
role = "github-workflow"

[installation-policy.required-claims]
repository = "myorg/gamma"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
        assert_eq!(config.installation_policies.len(), 1);
    }

    #[test]
    fn rejects_github_app_with_unknown_allowed_role() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "kubernetes"
audience = "idcat"
issuer = "https://kubernetes.default.svc"

[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
allowed-roles = ["buildkite"]
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(error.to_string(), "unknown role 'buildkite'");
    }

    #[test]
    fn rejects_github_app_without_allowed_roles() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "kubernetes"
audience = "idcat"
issuer = "https://kubernetes.default.svc"

[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "github-app 'default' must define at least one allowed-role, installation-policy or owner-policy"
        );
    }

    #[test]
    fn rejects_installation_policy_without_required_claims() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/alfa"
role = "github-workflow"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "installation-policy for github-app 'deployments' repository 'myorg/alfa' role 'github-workflow' must define at least one required-claim (or set allow-self-access)"
        );
    }

    /// A config with a single `[[owner-policy]]`, so owner-policy tests can vary just the policy.
    fn owner_policy_config(owner_policy: &str) -> String {
        format!(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

{owner_policy}
"#
        )
    }

    #[test]
    fn accepts_owner_policy_as_the_only_grant_for_a_github_app() {
        let config: Config = toml::from_str(&owner_policy_config(
            r#"
[[owner-policy]]
github-app = "deployments"
owner = "myorg"
role = "github-workflow"
allow-self-access = true

[owner-policy.permissions]
packages = "read"
"#,
        ))
        .unwrap();

        config.validate(false).unwrap();
    }

    #[test]
    fn rejects_owner_policy_without_permissions() {
        let config: Config = toml::from_str(&owner_policy_config(
            r#"
[[owner-policy]]
github-app = "deployments"
owner = "myorg"
role = "github-workflow"
allow-self-access = true
"#,
        ))
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "owner-policy for github-app 'deployments' owner 'myorg' role 'github-workflow' must define at least one permission under [owner-policy.permissions]; an owner-wide token without narrowed permissions is what allowed-roles already grants"
        );
    }

    #[test]
    fn rejects_owner_policy_without_required_claims_or_self_access() {
        let config: Config = toml::from_str(&owner_policy_config(
            r#"
[[owner-policy]]
github-app = "deployments"
owner = "myorg"
role = "github-workflow"

[owner-policy.permissions]
packages = "read"
"#,
        ))
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "owner-policy for github-app 'deployments' owner 'myorg' role 'github-workflow' must define at least one required-claim (or set allow-self-access)"
        );
    }

    #[test]
    fn rejects_owner_policy_with_a_repository_shaped_owner() {
        let config: Config = toml::from_str(&owner_policy_config(
            r#"
[[owner-policy]]
github-app = "deployments"
owner = "myorg/alfa"
role = "github-workflow"
allow-self-access = true

[owner-policy.permissions]
packages = "read"
"#,
        ))
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "owner-policy for github-app 'deployments' must define owner as an account name or a glob like 'myorg-*' or '*', without a '/'"
        );
    }

    #[test]
    fn rejects_owner_policy_that_redefines_the_self_access_claim() {
        let config: Config = toml::from_str(&owner_policy_config(
            r#"
[[owner-policy]]
github-app = "deployments"
owner = "myorg"
role = "github-workflow"
allow-self-access = true
required-claims = { repository_owner = "otherorg" }

[owner-policy.permissions]
packages = "read"
"#,
        ))
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "owner-policy for github-app 'deployments' owner 'myorg' role 'github-workflow' sets allow-self-access; required-claims must not also define 'repository_owner' (allow-self-access already constrains it to the requested owner)"
        );
    }

    #[test]
    fn rejects_owner_policy_that_sets_both_owner_and_owners() {
        let error = toml::from_str::<Config>(&owner_policy_config(
            r#"
[[owner-policy]]
github-app = "deployments"
owner = "myorg"
owners = ["myorg", "otherorg"]
role = "github-workflow"
allow-self-access = true

[owner-policy.permissions]
packages = "read"
"#,
        ))
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("owner-policy must specify either owner or owners, not both"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_owner_policy_referencing_an_unknown_github_app() {
        let config: Config = toml::from_str(&owner_policy_config(
            r#"
[[owner-policy]]
github-app = "missing"
owner = "myorg"
role = "github-workflow"
allow-self-access = true

[owner-policy.permissions]
packages = "read"
"#,
        ))
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "owner-policy references unknown github-app 'missing'"
        );
    }

    #[test]
    fn disable_auth_skips_authentication_and_required_claims_validation() {
        let config: Config = toml::from_str(
            r#"
[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
    }
}
