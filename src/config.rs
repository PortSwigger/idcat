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
    #[serde(rename = "human-role", default)]
    pub human_roles: Vec<HumanRoleConfig>,
    #[serde(rename = "human-policy", default)]
    pub human_policies: Vec<HumanPolicyConfig>,
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

/// A Teleport issuer whose tokens are presented by a *person*. Kept separate from `[[role]]`
/// (which `authzoo` validates for workload identities) so that a workload token can never satisfy
/// a human policy and a human token can never satisfy a workload one: the two are validated by
/// different code against different issuers, and neither namespace can name the other's roles.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct HumanRoleConfig {
    /// The idcat-local name a `[[human-policy]]` refers to.
    pub name: String,
    /// The exact `iss` the token must carry.
    pub issuer: String,
    /// The exact `aud` the token must carry. This is the Teleport *application uri*, which is not
    /// necessarily the hostname a person types.
    pub audience: String,
    /// The JWKS endpoint, given explicitly rather than discovered from the issuer.
    pub jwks_url: String,
    /// The exact Teleport role string that must appear in `roles-claim`.
    pub teleport_role: String,
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
    #[serde(default = "default_human_algorithms")]
    pub algorithms: Vec<HumanJwtAlgorithm>,
    /// A scalar claim naming the Teleport access request or session, recorded on issuance so an
    /// operator can join the approval to the token that followed it.
    pub request_id_claim: Option<String>,
    #[serde(rename = "required-claims", default)]
    pub required_claims: BTreeMap<String, authzoo::ClaimRequirement>,
}

/// Asymmetric signature algorithms only. A human role must never be validated against a shared
/// secret: anything able to verify such a token could also mint one.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
pub enum HumanJwtAlgorithm {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "RS384")]
    Rs384,
    #[serde(rename = "RS512")]
    Rs512,
    #[serde(rename = "PS256")]
    Ps256,
    #[serde(rename = "PS384")]
    Ps384,
    #[serde(rename = "PS512")]
    Ps512,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    Es384,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl HumanJwtAlgorithm {
    pub fn to_algorithm(self) -> jsonwebtoken::Algorithm {
        use jsonwebtoken::Algorithm;
        match self {
            Self::Rs256 => Algorithm::RS256,
            Self::Rs384 => Algorithm::RS384,
            Self::Rs512 => Algorithm::RS512,
            Self::Ps256 => Algorithm::PS256,
            Self::Ps384 => Algorithm::PS384,
            Self::Ps512 => Algorithm::PS512,
            Self::Es256 => Algorithm::ES256,
            Self::Es384 => Algorithm::ES384,
            Self::EdDsa => Algorithm::EdDSA,
        }
    }
}

/// Binds one exact repository to one exact Teleport role. Unlike `[[installation-policy]]` there
/// is no repository glob and no `allowed-roles` fallback: if this does not match, the request is
/// refused rather than retried against a broader path.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct HumanPolicyConfig {
    pub github_app: String,
    /// Exactly one repository in `owner/name` form. Globs are rejected at startup.
    pub repository: String,
    /// The `[[human-role]]` name that authorises this repository.
    pub human_role: String,
    // Keys are GitHub permission names (snake_case), not kebab-case.
    #[serde(default)]
    pub permissions: BTreeMap<String, String>,
}

fn default_roles_claim() -> String {
    "roles".to_string()
}

fn default_human_algorithms() -> Vec<HumanJwtAlgorithm> {
    vec![HumanJwtAlgorithm::Rs256]
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
        // A human-only deployment configures `[[human-role]]` and no workload `[[role]]`, so
        // either kind satisfies this.
        if !disable_auth && self.roles.is_empty() && self.human_roles.is_empty() {
            anyhow::bail!("at least one [[role]] or [[human-role]] entry is required");
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
            // Run the human checks first, so a misreferenced app or role reports the specific
            // problem rather than the generic "this app authorizes nothing" that follows from it.
            self.validate_human_config(&github_apps, &role_validator)?;
            for github_app in &self.github_apps {
                let has_installation_policy = self
                    .installation_policies
                    .iter()
                    .any(|installation_policy| installation_policy.github_app == github_app.name);
                let has_human_policy = self
                    .human_policies
                    .iter()
                    .any(|human_policy| human_policy.github_app == github_app.name);
                if github_app.allowed_roles.is_empty()
                    && !has_installation_policy
                    && !has_human_policy
                {
                    anyhow::bail!(
                        "github-app '{}' must define at least one allowed-role, installation-policy or human-policy",
                        github_app.name
                    );
                }
            }
        }
        Ok(())
    }

    /// Startup checks for the human path. Every one of these is a fail-closed condition: rather
    /// than narrowing a loose policy at request time, idcat refuses to start.
    fn validate_human_config(
        &self,
        github_apps: &std::collections::HashSet<String>,
        role_validator: &authzoo::TokenValidator,
    ) -> anyhow::Result<()> {
        let mut human_role_names = HashSet::new();
        for human_role in &self.human_roles {
            if human_role.name.is_empty() {
                anyhow::bail!("human-role names must not be empty");
            }
            if !human_role_names.insert(human_role.name.clone()) {
                anyhow::bail!("duplicate human-role '{}'", human_role.name);
            }
            // A shared name across the two namespaces would make `role = "x"` ambiguous to a
            // reader, and makes the allowed-roles overlap check below unreadable.
            if role_validator.roles().contains_key(&human_role.name) {
                anyhow::bail!(
                    "human-role '{}' has the same name as a [[role]]; workload and human role names must not overlap",
                    human_role.name
                );
            }
            if human_role.issuer.is_empty() {
                anyhow::bail!("human-role '{}' must define issuer", human_role.name);
            }
            if human_role.audience.is_empty() {
                anyhow::bail!(
                    "human-role '{}' must define audience (the Teleport application uri)",
                    human_role.name
                );
            }
            if !human_role.jwks_url.starts_with("https://") {
                anyhow::bail!(
                    "human-role '{}' jwks-url must be an https URL",
                    human_role.name
                );
            }
            if !human_role
                .jwks_url
                .ends_with(crate::human::TELEPORT_JWKS_PATH)
            {
                anyhow::bail!(
                    "human-role '{}' jwks-url must end in '{}'",
                    human_role.name,
                    crate::human::TELEPORT_JWKS_PATH
                );
            }
            if human_role.teleport_role.is_empty() {
                anyhow::bail!("human-role '{}' must define teleport-role", human_role.name);
            }
            if human_role.teleport_role.contains('*') || human_role.teleport_role.contains('?') {
                anyhow::bail!(
                    "human-role '{}' teleport-role must be an exact role name, not a pattern",
                    human_role.name
                );
            }
            if human_role.roles_claim.is_empty() {
                anyhow::bail!(
                    "human-role '{}' roles-claim must not be empty",
                    human_role.name
                );
            }
            if human_role.algorithms.is_empty() {
                anyhow::bail!(
                    "human-role '{}' must allow at least one algorithm",
                    human_role.name
                );
            }
            if matches!(human_role.request_id_claim.as_deref(), Some("")) {
                anyhow::bail!(
                    "human-role '{}' request-id-claim must not be empty when set",
                    human_role.name
                );
            }
            for (claim, requirement) in &human_role.required_claims {
                if claim.is_empty() {
                    anyhow::bail!(
                        "human-role '{}' required-claim names must not be empty",
                        human_role.name
                    );
                }
                if claim == &human_role.roles_claim {
                    anyhow::bail!(
                        "human-role '{}' required-claim '{}' duplicates roles-claim; role membership is checked against the array, not as a scalar",
                        human_role.name,
                        claim
                    );
                }
                requirement.validate(&human_role.name, claim)?;
            }
        }

        let mut seen_mappings: HashSet<(String, String, String)> = HashSet::new();
        let mut seen_repositories: HashSet<(String, String)> = HashSet::new();
        for human_policy in &self.human_policies {
            let repository = &human_policy.repository;
            if !github_apps.contains(&human_policy.github_app) {
                anyhow::bail!(
                    "human-policy references unknown github-app '{}'",
                    human_policy.github_app
                );
            }
            if repository.contains('*') || repository.contains('?') {
                anyhow::bail!(
                    "human-policy for github-app '{}' repository '{}' must name one exact repository; wildcards are not allowed on the human path",
                    human_policy.github_app,
                    repository
                );
            }
            match repository.split_once('/') {
                Some((owner, name))
                    if !owner.is_empty() && !name.is_empty() && !name.contains('/') => {}
                _ => anyhow::bail!(
                    "human-policy for github-app '{}' repository '{}' must be in owner/name form",
                    human_policy.github_app,
                    repository
                ),
            }
            if !human_role_names.contains(&human_policy.human_role) {
                anyhow::bail!(
                    "human-policy for repository '{}' references unknown human-role '{}'",
                    repository,
                    human_policy.human_role
                );
            }
            // Without this, a human policy would inherit whatever the App's installation grants,
            // which is exactly the broad path the pilot is meant to avoid.
            if human_policy.permissions.is_empty() {
                anyhow::bail!(
                    "human-policy for github-app '{}' repository '{}' must define at least one permission",
                    human_policy.github_app,
                    repository
                );
            }
            for (permission, value) in &human_policy.permissions {
                if permission.is_empty() {
                    anyhow::bail!(
                        "human-policy for github-app '{}' repository '{}' permission names must not be empty",
                        human_policy.github_app,
                        repository
                    );
                }
                if value.is_empty() {
                    anyhow::bail!(
                        "human-policy for github-app '{}' repository '{}' permission '{}' must define a value",
                        human_policy.github_app,
                        repository,
                        permission
                    );
                }
                if !known_github_permissions().contains(permission) {
                    warn!(
                        "human-policy for github-app '{}' repository '{}' uses unrecognised permission '{}'",
                        human_policy.github_app, repository, permission
                    );
                }
                if !KNOWN_PERMISSION_VALUES.contains(&value.as_str()) {
                    warn!(
                        "human-policy for github-app '{}' repository '{}' permission '{}' has unrecognised value '{}'",
                        human_policy.github_app, repository, permission, value
                    );
                }
            }
            // A GitHub App that grants the same role a broad token through `allowed-roles` would
            // make the narrow human policy pointless, since the broad path is checked first.
            let github_app = self
                .github_apps
                .iter()
                .find(|github_app| github_app.name == human_policy.github_app)
                .expect("github-app presence was checked above");
            if github_app.allowed_roles.contains(&human_policy.human_role) {
                anyhow::bail!(
                    "github-app '{}' grants human-role '{}' through allowed-roles; a human-policy must be the only path to that role",
                    github_app.name,
                    human_policy.human_role
                );
            }
            let mapping = (
                human_policy.github_app.clone(),
                repository.clone(),
                human_policy.human_role.clone(),
            );
            if !seen_mappings.insert(mapping) {
                anyhow::bail!(
                    "duplicate human-policy for github-app '{}' repository '{}' human-role '{}'",
                    human_policy.github_app,
                    repository,
                    human_policy.human_role
                );
            }
            // Two roles reaching the same repository, or one role reaching it through two Apps,
            // makes "who approved this" ambiguous in the issuance record.
            if !seen_repositories.insert((human_policy.github_app.clone(), repository.clone())) {
                anyhow::bail!(
                    "github-app '{}' has more than one human-policy for repository '{}'; each repository must map to exactly one human-role",
                    human_policy.github_app,
                    repository
                );
            }
        }
        Ok(())
    }
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
            "github-app 'default' must define at least one allowed-role, installation-policy or human-policy"
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

/// Startup validation of the human path. Every case here is a configuration idcat must refuse to
/// start with, rather than narrow silently at request time.
#[cfg(test)]
mod human_config_tests {
    use super::*;

    const BASE: &str = r#"
[[github-app]]
name = "source-reader"
app-id = 42
secret-key = "private-key.pem"

[[human-role]]
name = "pilot-repo-reader"
issuer = "https://teleport.example.invalid"
audience = "https://idcat.teleport.example.invalid:443"
jwks-url = "https://teleport.example.invalid/.well-known/jwks.json"
teleport-role = "github-app-token-pilot-repo"
"#;

    fn config(extra: &str) -> anyhow::Result<()> {
        let config: Config = toml::from_str(&format!("{BASE}{extra}"))?;
        config.validate(false)
    }

    const VALID_POLICY: &str = r#"
[[human-policy]]
github-app = "source-reader"
repository = "myorg/pilot"
human-role = "pilot-repo-reader"

[human-policy.permissions]
contents = "read"
"#;

    #[test]
    fn accepts_one_exact_repository_with_a_permission_map() {
        config(VALID_POLICY).unwrap();
    }

    #[test]
    fn rejects_a_wildcard_repository() {
        for repository in ["*", "myorg/*", "myorg/pilot?"] {
            let error = config(&format!(
                r#"
[[human-policy]]
github-app = "source-reader"
repository = "{repository}"
human-role = "pilot-repo-reader"

[human-policy.permissions]
contents = "read"
"#
            ))
            .unwrap_err();
            assert!(
                error.to_string().contains("one exact repository"),
                "repository '{repository}' must be refused, got: {error}"
            );
        }
    }

    #[test]
    fn rejects_a_repository_that_is_not_in_owner_name_form() {
        let error = config(
            r#"
[[human-policy]]
github-app = "source-reader"
repository = "pilot"
human-role = "pilot-repo-reader"

[human-policy.permissions]
contents = "read"
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("owner/name form"), "{error}");
    }

    #[test]
    fn rejects_an_empty_permission_map() {
        let error = config(
            r#"
[[human-policy]]
github-app = "source-reader"
repository = "myorg/pilot"
human-role = "pilot-repo-reader"
"#,
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("at least one permission"),
            "an empty permission map would inherit the whole installation: {error}"
        );
    }

    #[test]
    fn rejects_a_second_policy_for_the_same_repository() {
        let error = config(&format!(
            r#"{VALID_POLICY}
[[human-policy]]
github-app = "source-reader"
repository = "myorg/pilot"
human-role = "pilot-repo-reader"

[human-policy.permissions]
contents = "write"
"#
        ))
        .unwrap_err();

        assert!(
            error.to_string().contains("duplicate human-policy"),
            "{error}"
        );
    }

    #[test]
    fn rejects_two_roles_reaching_the_same_repository() {
        let error = config(&format!(
            r#"
[[human-role]]
name = "second-reader"
issuer = "https://teleport.example.invalid"
audience = "https://idcat.teleport.example.invalid:443"
jwks-url = "https://teleport.example.invalid/.well-known/jwks.json"
teleport-role = "another-teleport-role"
{VALID_POLICY}
[[human-policy]]
github-app = "source-reader"
repository = "myorg/pilot"
human-role = "second-reader"

[human-policy.permissions]
contents = "read"
"#
        ))
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("more than one human-policy for repository"),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_github_app_that_also_grants_the_role_through_allowed_roles() {
        // `allowed-roles` is checked before any policy on the workload path, so an App granting
        // the same name there would make the narrow human policy unreachable and pointless.
        let error = toml::from_str::<Config>(&format!(
            r#"
[[role]]
name = "pilot-repo-reader"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "secret"
algorithms = ["HS256"]

[[github-app]]
name = "source-reader"
app-id = 42
secret-key = "private-key.pem"
allowed-roles = ["pilot-repo-reader"]

[[human-role]]
name = "pilot-repo-reader"
issuer = "https://teleport.example.invalid"
audience = "https://idcat.teleport.example.invalid:443"
jwks-url = "https://teleport.example.invalid/.well-known/jwks.json"
teleport-role = "github-app-token-pilot-repo"
{VALID_POLICY}"#
        ))
        .unwrap()
        .validate(false)
        .unwrap_err();

        assert!(
            error.to_string().contains("must not overlap"),
            "a name shared by [[role]] and [[human-role]] must be refused: {error}"
        );
    }

    #[test]
    fn rejects_an_app_whose_allowed_roles_name_the_human_role() {
        // No `[[role]]` of this name exists, so `allowed-roles` cannot resolve it. Together with
        // `rejects_a_github_app_that_also_grants_the_role_through_allowed_roles` (which covers the
        // case where such a `[[role]]` does exist) this closes both halves: an App can never grant
        // a broad token under the name a human-policy uses.
        let error = config(&format!(
            r#"
[[github-app]]
name = "second-app"
app-id = 43
secret-key = "private-key.pem"
allowed-roles = ["pilot-repo-reader"]
{VALID_POLICY}"#
        ))
        .unwrap_err();

        assert!(
            error.to_string().contains("unknown role"),
            "an allowed-role naming a human-role must not resolve: {error}"
        );
    }

    #[test]
    fn rejects_a_jwks_url_that_is_not_the_teleport_jwks_path() {
        for jwks_url in [
            "https://teleport.example.invalid/.well-known/openid-configuration",
            "https://teleport.example.invalid/jwks",
            "http://teleport.example.invalid/.well-known/jwks.json",
        ] {
            let error = toml::from_str::<Config>(&format!(
                r#"
[[github-app]]
name = "source-reader"
app-id = 42
secret-key = "private-key.pem"

[[human-role]]
name = "pilot-repo-reader"
issuer = "https://teleport.example.invalid"
audience = "https://idcat.teleport.example.invalid:443"
jwks-url = "{jwks_url}"
teleport-role = "github-app-token-pilot-repo"
{VALID_POLICY}"#
            ))
            .unwrap()
            .validate(false)
            .unwrap_err();

            assert!(
                error.to_string().contains("jwks-url"),
                "jwks-url '{jwks_url}' must be refused, got: {error}"
            );
        }
    }

    #[test]
    fn rejects_a_teleport_role_pattern() {
        let error = toml::from_str::<Config>(&format!(
            r#"
[[github-app]]
name = "source-reader"
app-id = 42
secret-key = "private-key.pem"

[[human-role]]
name = "pilot-repo-reader"
issuer = "https://teleport.example.invalid"
audience = "https://idcat.teleport.example.invalid:443"
jwks-url = "https://teleport.example.invalid/.well-known/jwks.json"
teleport-role = "github-app-token-*"
{VALID_POLICY}"#
        ))
        .unwrap()
        .validate(false)
        .unwrap_err();

        assert!(error.to_string().contains("exact role name"), "{error}");
    }

    #[test]
    fn rejects_an_unknown_human_role_reference() {
        let error = config(
            r#"
[[human-policy]]
github-app = "source-reader"
repository = "myorg/pilot"
human-role = "no-such-role"

[human-policy.permissions]
contents = "read"
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unknown human-role"), "{error}");
    }

    #[test]
    fn rejects_an_unknown_github_app_reference() {
        let error = config(
            r#"
[[human-policy]]
github-app = "no-such-app"
repository = "myorg/pilot"
human-role = "pilot-repo-reader"

[human-policy.permissions]
contents = "read"
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unknown github-app"), "{error}");
    }

    #[test]
    fn rejects_an_hmac_algorithm_for_a_human_role() {
        // A shared secret able to verify a human token could also mint one.
        let error = toml::from_str::<Config>(&format!(
            r#"
[[github-app]]
name = "source-reader"
app-id = 42
secret-key = "private-key.pem"

[[human-role]]
name = "pilot-repo-reader"
issuer = "https://teleport.example.invalid"
audience = "https://idcat.teleport.example.invalid:443"
jwks-url = "https://teleport.example.invalid/.well-known/jwks.json"
teleport-role = "github-app-token-pilot-repo"
algorithms = ["HS256"]
{VALID_POLICY}"#
        ))
        .unwrap_err();

        assert!(
            error.to_string().contains("HS256") || error.to_string().contains("unknown variant"),
            "an HMAC algorithm must not parse for a human role: {error}"
        );
    }

    #[test]
    fn rejects_a_required_claim_that_shadows_the_roles_claim() {
        let error = toml::from_str::<Config>(&format!(
            r#"
[[github-app]]
name = "source-reader"
app-id = 42
secret-key = "private-key.pem"

[[human-role]]
name = "pilot-repo-reader"
issuer = "https://teleport.example.invalid"
audience = "https://idcat.teleport.example.invalid:443"
jwks-url = "https://teleport.example.invalid/.well-known/jwks.json"
teleport-role = "github-app-token-pilot-repo"

[human-role.required-claims]
roles = "github-app-token-pilot-repo"
{VALID_POLICY}"#
        ))
        .unwrap()
        .validate(false)
        .unwrap_err();

        assert!(
            error.to_string().contains("duplicates roles-claim"),
            "a scalar requirement on the roles claim must be refused: {error}"
        );
    }

    #[test]
    fn a_github_app_may_be_authorized_by_a_human_policy_alone() {
        // Without this, adding a human-only App would demand a pointless workload role.
        config(VALID_POLICY).unwrap();
    }
}
