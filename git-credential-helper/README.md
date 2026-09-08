# git-credential-idcat

`git-credential-idcat` is a Git credential helper for using private GitHub repositories through
an idcat service. For more information about idcat, please see https://github.com/nresare/idcat.
When Git asks for credentials for an HTTPS GitHub remote, the helper picks up a
bearer token from a local file or command and uses that with a remote idcat service to exchange it for
an installation token that can be used to authenticate with GitHub for push and pull operations.

Requests for non-GitHub hosts, non-HTTPS URLs, or GitHub URLs without an owner/repository path are
ignored so that other credential helpers can handle them.

## Installation

```sh
cargo install git-credential-idcat
```

Configure Git to use the helper:

```sh
git config --global credential.helper idcat
```

To use a non-default configuration file:

```sh
git config --global credential.helper "idcat --config /path/to/credential-helper.toml"
```

## Configuration

By default, the helper reads:

```text
~/.config/idcat/credential-helper.toml
```

Example:

```toml
github-app = "deployments"
idcat-endpoint = "https://idcat.example.com"
token-path = "/var/run/secrets/tokens/idcat"
```

`github-app` selects the GitHub App configured in idcat. `idcat-endpoint` is the base URL of the
idcat service.

Exactly one token source must be configured.

Read the token from a file:

```toml
token-path = "/var/run/secrets/tokens/idcat"
```

Or run a program and use its standard output:

```toml
token-executable = "/usr/bin/kubectl"
token-args = ["create", "token", "idcat-client"]
```

`token-path` reads a bearer token accepted by idcat from the filesystem, such as a mounted
Kubernetes service account token. `token-executable` runs a fixed executable with an explicit
argument array. No shell is involved, so nothing in the configuration is word-split, globbed or
substituted, and each argument reaches the program exactly as written.

### Migrating from `token-command` (deprecated)

`token-command` ran its value through `/bin/sh -c`. It still works and existing configuration keeps
working unchanged, but it logs a deprecation warning at startup and will be removed. Rewrite it as
an executable and an argument array:

```toml
# Before
token-command = "kubectl create token idcat-client"

# After
token-executable = "/usr/bin/kubectl"
token-args = ["create", "token", "idcat-client"]
```

Setting more than one of `token-path`, `token-executable` and `token-command` is an error, as is
setting `token-args` without `token-executable`.

### Restricting the helper to one repository

```toml
repository = "myorg/pilot"
```

When `repository` is set, the helper produces a credential for that repository and nothing else.
For any other repository it prints nothing, so Git receives no credential from it. Owner and
repository names are compared case-insensitively, as GitHub treats them. When `repository` is
unset the helper answers for any GitHub repository, which is the pre-existing behaviour; a
deployment that mints tokens for a *person* should set it.

Scope Git's own configuration to match, so the helper is offered only the requests it is for, and
so no other helper is consulted for them:

```sh
# Match credentials by full path, not just by host, so this block applies to one repository.
git config --global credential.useHttpPath true

# Clear any inherited helpers for this repository, then add only this one.
git config --global --unset-all credential.https://github.com/myorg/pilot.helper
git config --global --add credential.https://github.com/myorg/pilot.helper ""
git config --global --add credential.https://github.com/myorg/pilot.helper idcat
```

The empty first value clears helpers inherited from broader scopes, so a global `store` or
`osxkeychain` helper is neither consulted for this repository nor offered the token.

When Git accesses `https://github.com/OWNER/REPO.git`, the helper calls:

```text
POST {idcat-endpoint}/installation-token/{github-app}/OWNER/REPO
```

with the configured token as the bearer token. The response body is returned to Git as the
password, with `x-access-token` as the username.

## What the helper does not do

`store` and `erase` are accepted and do nothing: the helper holds no state, and a token it returned
is not written anywhere. The token is never passed as a command-line argument, so it cannot appear
in process listings or shell history, and it is never logged — a failing token source is reported
by exit status alone, without echoing what it printed.

## License

MIT
