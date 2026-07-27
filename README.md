# idcat

`idcat` is a service for safely delegating GitHub App permissions

It allows authenticated callers to get GitHub App installation access tokens without having
direct access to the app’s private signing key. Instead, services and workflows are authenticated with
idcat using JWT bearer tokens. Based on the issuer and claims in those tokens, idcat can
issue installation tokens with precisely the permissions needed for a particular use case.

This makes it possible to grant applications and services controlled access to GitHub through
a GitHub App, while keeping the app’s signing credentials centralised and protected.

## Features

- A High-performance, high-availability service written in Rust using Tokio and Axum
- Signing keys can optionally be stored in AWS KMS, making it more difficult for an attacker to get hold of sensitive
  material
- The centralised configuration setup encourages granting only permissions that are actually needed
- The ability to bridge webhook notifications from GitHub into the NATS messaging service 

## Configuration

```toml
private-key-directory = "/var/run/secrets/idcat"

[[role]]
name = "kubernetes-default"
audience = "idcat"
issuer = "https://kubernetes.default.svc"
claims = {sub = "system:serviceaccount:default:default"}

[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"

[[github-app]]
name = "deployments"
app-id = 123456
secret-key = "deployments-private-key.pem"
allowed-roles = ["kubernetes-default"]

[[installation-policy]]
github-app = "deployments"
repositories = ["myorg/alfa", "myorg/beta"]
role = "github-workflow"
required-claims = { repository = "myorg/gamma" }
```

See `idcat.toml.example` for a fuller configuration with multiple roles and GitHub Apps.
List multiple entries in `allowed-roles` to allow alternative authentication methods or
role trust requirements for the same GitHub App.
Use `[[installation-policy]]` to grant a role only for one installed app/repository
combination, with additional required token claims. Set either `repository = "owner/name"`
or `repositories = ["owner/name", "owner/other"]`; the request may match any configured
repository pattern. For example, a request for `deployments` on `myorg/alfa` can require
the token to satisfy `github-workflow` and also
carry `repository = "myorg/gamma"`. App-level `allowed-roles` still grant access to every
repository installation for that GitHub App.

Mount the private keys as files. For example, in Kubernetes this could be a Secret volume mounted at `private-key-directory`, but `idcat` only reads files from the filesystem.

```sh
kubectl create secret generic idcat \
  --from-file=private-key.pem=/path/to/github-app-private-key.pem
```

The application does not need Kubernetes API permissions to read private keys.

When built with the `kms` feature, `key-source` may be set to `kms`. In that mode,
`secret-key` selects an AWS KMS alias instead of a filesystem path. Values without
the `alias/` prefix are treated as alias names, so `secret-key = "deployments"`
uses `alias/deployments`. AWS credentials and region are loaded from the ambient
AWS SDK configuration.

## API

```sh
curl -X POST \
  -H "Authorization: Bearer $KUBERNETES_JWT" \
  http://localhost:8080/installation-token/deployments/github_user/repo_name
```

The response body is the GitHub installation token:

```text
ghs_...
```

To request one installation token scoped to several repositories owned by the
same account, omit the repository from the URL and provide repository names in
the JSON request body:

```sh
curl -X POST \
  -H "Authorization: Bearer $KUBERNETES_JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "repositories": ["repo_one", "repo_two"],
    "permissions": {
      "contents": "read",
      "pull_requests": "write"
    }
  }' \
  http://localhost:8080/installation-token/deployments/github_user
```

Every repository must be authorized by the caller's role and installation
policies. The requested permissions must be allowed for every repository. When
`permissions` is omitted, idcat uses the shared permission policy; if the
repositories have different restricted policies, the request must specify an
explicit common down-scope. The response is a JSON document containing the
token, expiry, permissions, and GitHub repository selection metadata.

To proxy a repository-scoped GitHub API request through an installation token, prefix the GitHub
`/repos/{owner}/{repo}` path with `/proxy/{github-app}`. The GitHub app name selects the
configured GitHub App and its allowed roles, while the owner/repo pair comes from the proxied
GitHub API path:

```sh
curl -X GET \
  -H "Authorization: Bearer $KUBERNETES_JWT" \
  http://localhost:8080/proxy/deployments/repos/github_user/repo_name/contents/README.md
```

## Webhooks

idcat can receive GitHub webhook callbacks and bridge them into NATS. GitHub
should be configured to deliver callbacks to `/webhook/{github-app}`, where
`{github-app}` matches a configured `[[github-app]]` name:

```text
https://idcat.example.com/webhook/deployments
```

Each GitHub App opts in to bridging independently by setting `webhook-target`
in its config block. The NATS connection itself is configured once in a
top-level `[nats]` block and shared by every app that opts in:

```toml
[nats]
endpoint = "nats://nats.example.com:4222"
subject-base = "idcat.github.webhook"
token-path = "/var/run/secrets/idcat/nats-token"

[[github-app]]
name = "deployments"
app-id = 123456
secret-key = "deployments-private-key.pem"
webhook-target = "nats"
```

If the GitHub App is configured with a webhook secret, set
`webhook-validation-secret-file` to the path of a file containing that secret.
idcat then verifies the `X-Hub-Signature-256` header on each delivery
([GitHub docs](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries))
and rejects deliveries that do not match. The secret is read from the file on
every delivery, so it can be rotated without restarting idcat.

```toml
[[github-app]]
name = "deployments"
app-id = 123456
secret-key = "deployments-private-key.pem"
webhook-target = "nats"
webhook-validation-secret-file = "/var/run/secrets/idcat/deployments-webhook-secret"
```

## Running

```sh
cargo run -- --config-file idcat.toml
```

For local testing, authentication and role checks can be bypassed:

```sh
cargo run -- --config-file idcat.toml --disable-auth
```

Use `--debug` to log detailed installation-token flow steps:

```sh
cargo run -- --config-file idcat.toml --debug
```

GitHub App installation IDs are cached in memory after the first lookup. Installation tokens are
cached in memory for 50 minutes per GitHub app and repo.

## License

MIT
