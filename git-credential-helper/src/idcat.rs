use crate::config::Config;
use crate::credential::Repo;
use anyhow::{Context, anyhow, bail};
use tracing::info;
use url::Url;

pub fn fetch_installation_token(
    config: &Config,
    repo: &Repo,
    bearer_token: &str,
) -> anyhow::Result<String> {
    let url = installation_token_url(config, repo)?;
    info!(
        endpoint = %config.idcat_endpoint,
        github_app = %config.github_app,
        repo = %format!("{}/{}", repo.owner, repo.name),
        "obtaining installation token from idcat"
    );
    let response = reqwest::blocking::Client::new()
        .post(url)
        .bearer_auth(bearer_token)
        .send()
        .context("failed to request installation token from idcat")?;

    let status = response.status();
    let body = response
        .text()
        .context("failed to read idcat installation token response")?;

    if !status.is_success() {
        bail!("idcat returned HTTP {status}: {body}");
    }

    let token = body.trim();
    if token.is_empty() {
        bail!("idcat returned an empty installation token");
    }

    info!(
        endpoint = %config.idcat_endpoint,
        github_app = %config.github_app,
        repo = %format!("{}/{}", repo.owner, repo.name),
        "installation token obtained from idcat"
    );

    Ok(token.to_owned())
}

fn installation_token_url(config: &Config, repo: &Repo) -> anyhow::Result<Url> {
    let endpoint = if config.idcat_endpoint.ends_with('/') {
        config.idcat_endpoint.clone()
    } else {
        format!("{}/", config.idcat_endpoint)
    };
    let mut url = Url::parse(&endpoint).context("idcat-endpoint is not a valid URL")?;
    url.path_segments_mut()
        .map_err(|_| anyhow!("idcat-endpoint cannot be used as a base URL"))?
        .pop_if_empty()
        .extend([
            "installation-token",
            &config.github_app,
            &repo.owner,
            &repo.name,
        ]);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TokenSource;

    #[test]
    fn builds_installation_token_url() {
        let config = Config {
            github_app: "deployments".to_owned(),
            idcat_endpoint: "https://idcat.example.test/base".to_owned(),
            repository: None,
            token_source: TokenSource::ShellCommand("unused".to_owned()),
        };
        let repo = Repo {
            owner: "noa".to_owned(),
            name: "idcat".to_owned(),
        };

        assert_eq!(
            installation_token_url(&config, &repo)
                .expect("url builds")
                .as_str(),
            "https://idcat.example.test/base/installation-token/deployments/noa/idcat"
        );
    }
}
