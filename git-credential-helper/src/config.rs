use anyhow::{Context, anyhow, bail};
use serde::Deserialize;
use std::env;
use std::io::ErrorKind;
use std::path::PathBuf;
use tracing::warn;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawConfig {
    github_app: String,
    idcat_endpoint: String,
    /// The one repository this helper will produce a credential for, as `owner/name`. When unset
    /// the helper answers for any GitHub repository, which is the pre-existing behaviour; a
    /// deployment that mints tokens for a person must set it.
    repository: Option<String>,
    token_path: Option<PathBuf>,
    /// Deprecated. Runs through `/bin/sh -c`, which puts the command — and anything it
    /// interpolates — through a shell. Replaced by `token-executable` and `token-args`.
    token_command: Option<String>,
    token_executable: Option<PathBuf>,
    #[serde(default)]
    token_args: Vec<String>,
}

#[derive(Debug)]
pub struct Config {
    pub github_app: String,
    pub idcat_endpoint: String,
    pub repository: Option<Repository>,
    pub token_source: TokenSource,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Repository {
    pub owner: String,
    pub name: String,
}

#[derive(Debug)]
pub enum TokenSource {
    Path(PathBuf),
    /// A fixed executable invoked with an explicit argument array. No shell is involved, so
    /// nothing in the configuration is subject to word splitting, globbing or substitution.
    Program {
        executable: PathBuf,
        args: Vec<String>,
    },
    /// Deprecated shell form, accepted during the migration window.
    ShellCommand(String),
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let path = match path {
            Some(path) => path,
            None => default_config_path()?,
        };
        let config = match std::fs::read_to_string(&path) {
            Ok(config) => config,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                bail!("configuration file not found: {}", path.display());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read {}", path.display()));
            }
        };
        let config: RawConfig = toml::from_str(&config)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        config.try_into()
    }
}

impl TryFrom<RawConfig> for Config {
    type Error = anyhow::Error;

    fn try_from(config: RawConfig) -> Result<Self, Self::Error> {
        let sources_set = [
            config.token_path.is_some(),
            config.token_command.is_some(),
            config.token_executable.is_some(),
        ]
        .into_iter()
        .filter(|set| *set)
        .count();
        if sources_set == 0 {
            bail!("configuration must set one of token-path, token-executable or token-command");
        }
        if sources_set > 1 {
            bail!(
                "configuration must set only one of token-path, token-executable or token-command"
            );
        }
        if !config.token_args.is_empty() && config.token_executable.is_none() {
            bail!("token-args requires token-executable");
        }

        let token_source = match (
            config.token_path,
            config.token_executable,
            config.token_command,
        ) {
            (Some(path), None, None) => TokenSource::Path(path),
            (None, Some(executable), None) => {
                if executable.as_os_str().is_empty() {
                    bail!("token-executable must not be empty");
                }
                TokenSource::Program {
                    executable,
                    args: config.token_args,
                }
            }
            (None, None, Some(command)) => {
                if command.is_empty() {
                    bail!("token-command must not be empty");
                }
                warn!(
                    "token-command is deprecated and runs through /bin/sh; \
                     replace it with token-executable and token-args"
                );
                TokenSource::ShellCommand(command)
            }
            _ => unreachable!("the count check above rejects every other combination"),
        };

        let repository = config.repository.map(parse_repository).transpose()?;
        if repository.is_none() {
            warn!(
                "no repository is configured; this helper will answer for any GitHub repository. \
                 Set repository = \"owner/name\" to scope it to one."
            );
        }

        Ok(Self {
            github_app: config.github_app,
            idcat_endpoint: config.idcat_endpoint,
            repository,
            token_source,
        })
    }
}

fn parse_repository(repository: String) -> anyhow::Result<Repository> {
    let Some((owner, name)) = repository.split_once('/') else {
        bail!("repository must be in owner/name form, got '{repository}'");
    };
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        bail!("repository must be in owner/name form, got '{repository}'");
    }
    if repository.contains('*') || repository.contains('?') {
        bail!("repository must name one exact repository, got '{repository}'");
    }
    Ok(Repository {
        owner: owner.to_owned(),
        name: name.to_owned(),
    })
}

fn default_config_path() -> anyhow::Result<PathBuf> {
    let home = env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("idcat")
        .join("credential-helper.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_config() -> RawConfig {
        RawConfig {
            github_app: "deployments".to_owned(),
            idcat_endpoint: "https://idcat.example.test".to_owned(),
            repository: None,
            token_path: None,
            token_command: None,
            token_executable: None,
            token_args: Vec::new(),
        }
    }

    #[test]
    fn accepts_token_path() {
        let config = RawConfig {
            token_path: Some("/var/run/secrets/tokens/idcat".into()),
            ..raw_config()
        };

        let config = Config::try_from(config).expect("config validates");

        assert!(matches!(config.token_source, TokenSource::Path(_)));
    }

    #[test]
    fn accepts_token_executable_with_args() {
        let config = RawConfig {
            token_executable: Some("/usr/local/bin/tsh".into()),
            token_args: vec![
                "apps".to_owned(),
                "config".to_owned(),
                "--format=json".to_owned(),
            ],
            ..raw_config()
        };

        let config = Config::try_from(config).expect("config validates");

        match config.token_source {
            TokenSource::Program { executable, args } => {
                assert_eq!(executable, PathBuf::from("/usr/local/bin/tsh"));
                assert_eq!(args, ["apps", "config", "--format=json"]);
            }
            other => panic!("expected a Program token source, got {other:?}"),
        }
    }

    #[test]
    fn accepts_token_executable_without_args() {
        let config = RawConfig {
            token_executable: Some("/usr/local/bin/print-token".into()),
            ..raw_config()
        };

        let config = Config::try_from(config).expect("config validates");

        match config.token_source {
            TokenSource::Program { args, .. } => assert!(args.is_empty()),
            other => panic!("expected a Program token source, got {other:?}"),
        }
    }

    #[test]
    fn still_accepts_the_deprecated_token_command() {
        // The migration is backwards compatible: an existing configuration keeps working, with a
        // warning, rather than failing at startup.
        let config = RawConfig {
            token_command: Some("cat /var/run/secrets/tokens/idcat".to_owned()),
            ..raw_config()
        };

        let config = Config::try_from(config).expect("the deprecated form must keep working");

        assert!(matches!(config.token_source, TokenSource::ShellCommand(_)));
    }

    #[test]
    fn rejects_missing_token_source() {
        let error = Config::try_from(raw_config()).expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("must set one of token-path, token-executable or token-command"),
            "{error}"
        );
    }

    #[test]
    fn rejects_multiple_token_sources() {
        let config = RawConfig {
            token_path: Some("/var/run/secrets/tokens/idcat".into()),
            token_command: Some("cat /var/run/secrets/tokens/idcat".to_owned()),
            ..raw_config()
        };

        let error = Config::try_from(config).expect_err("config should be rejected");

        assert!(error.to_string().contains("only one of"), "{error}");
    }

    #[test]
    fn rejects_token_executable_combined_with_token_command() {
        let config = RawConfig {
            token_executable: Some("/usr/local/bin/tsh".into()),
            token_command: Some("tsh apps config".to_owned()),
            ..raw_config()
        };

        let error = Config::try_from(config).expect_err("config should be rejected");

        assert!(error.to_string().contains("only one of"), "{error}");
    }

    #[test]
    fn rejects_token_args_without_token_executable() {
        let config = RawConfig {
            token_path: Some("/var/run/secrets/tokens/idcat".into()),
            token_args: vec!["--format=json".to_owned()],
            ..raw_config()
        };

        let error = Config::try_from(config).expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("token-args requires token-executable"),
            "{error}"
        );
    }

    #[test]
    fn accepts_an_exact_repository() {
        let config = RawConfig {
            repository: Some("myorg/pilot".to_owned()),
            token_path: Some("/var/run/secrets/tokens/idcat".into()),
            ..raw_config()
        };

        let config = Config::try_from(config).expect("config validates");

        assert_eq!(
            config.repository,
            Some(Repository {
                owner: "myorg".to_owned(),
                name: "pilot".to_owned()
            })
        );
    }

    #[test]
    fn rejects_a_repository_that_is_not_owner_name() {
        for repository in ["pilot", "myorg/", "/pilot", "myorg/pilot/extra"] {
            let config = RawConfig {
                repository: Some(repository.to_owned()),
                token_path: Some("/var/run/secrets/tokens/idcat".into()),
                ..raw_config()
            };

            assert!(
                Config::try_from(config).is_err(),
                "repository '{repository}' must be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_wildcard_repository() {
        let config = RawConfig {
            repository: Some("myorg/*".to_owned()),
            token_path: Some("/var/run/secrets/tokens/idcat".into()),
            ..raw_config()
        };

        assert!(Config::try_from(config).is_err());
    }
}
