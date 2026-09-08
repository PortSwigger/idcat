# Human GitHub App token pilot

Lets a Teleport-authenticated person obtain a GitHub App installation token for **one exact
repository**, after the matching repository-owner approval. The existing workload path is
unchanged.

This document covers what an operator and a requester need to know. The configuration reference is
in [`idcat.toml.example`](../idcat.toml.example); the credential-helper side is in
[`git-credential-helper/README.md`](../git-credential-helper/README.md).

## What is deliberately not built

* No service-wide `authzoo` rewrite. The human path has its own validator; the workload path is
  untouched. Revisit only if the load test below shows the pilot boundary is insufficient.
* No vault or interface for revoking an individual installation token. The pilot accepts a
  one-hour bearer-token residual.
* No endpoint deletion or rights management for cloned source.
* No central Security approval step, and no monitoring of individual Git activity.
* No multi-repository bundles. Prove one repository first.

## The timebox, stated truthfully

Set **both** on the Teleport role:

```yaml
spec:
  options:
    max_session_ttl: 1h
  allow:
    request:
      max_duration: 1h
```

`max_duration` bounds how long the approval can be used to start a session; `max_session_ttl`
bounds the session itself. Setting only one leaves the other at its default and the hour is not
real.

What the hour actually does:

* After it ends, **no new session can start** under that approval.
* An installation token already issued **expires within the hour** — GitHub installation tokens
  last at most one hour from issue, and idcat does not extend them.

What the hour does **not** do:

* It does **not** remove source already cloned to the endpoint, and it does not remove the
  reachable history that came with it. Both remain on the machine after access expires, and both
  remain Restricted data.
* It does **not** revoke a token that has already been handed out. The token stops working when it
  expires, not when the approval does.

The request text shown to the approver and the requester must say this plainly. Wording that
implies the hour "removes access to the code" is wrong and must not be used.

## Emergency stop

**Suspend the dedicated GitHub App installation.** That is the documented emergency response: it
takes effect immediately for the whole App and needs no per-token machinery.

GitHub also exposes immediate revocation of a single installation token
(`DELETE /installation/token`), which is available if a specific token needs to be killed. A
per-token revocation service is not required for this pilot and is not built.

## Boundary and availability

The human route must be reachable **only** through the Teleport Application Service. It must not be
exposed to the internet, and it must not be reachable from the cluster network at large.

Configure, at the edge in front of idcat:

* a request rate limit on `/human/installation-token/`;
* strict outbound timeouts.

The reason is specific. `authzoo` validates a token once per configured role, and when a role has
no `validation-key` it fetches `{issuer}/.well-known/openid-configuration` **on every validation** —
only the resulting JWKS key is cached, not the discovery response. An unauthenticated flood of
invalid tokens against a route that reaches `authzoo` therefore multiplies into blocking outbound
requests on worker threads. The human path avoids this (one issuer chosen from configuration, one
parse, a cached JWKS), but existing workload consumers still run through `authzoo` on the same
runtime.

Before the pilot goes live, run the bounded invalid-token load test:

```sh
cargo run --example human_route_load_test -- --help
```

It requires the owner-supplied request ceiling, duration, permitted latency change and environment
name, and refuses to run without them or against anything that looks like production. It exits
non-zero if the measured workload p95 increase exceeds the permitted change — which is the signal
to complete the wider validator repair before live use.

## What must be supplied before this can be deployed

The code is complete and tested against synthetic tokens. These values are deployment inputs and
are **not** invented here:

| Input | Needed for |
| --- | --- |
| The pilot repository (`owner/name`) | `[[human-policy]]` `repository` |
| The owning team's reviewer role | Teleport `request.roles` reviewer configuration |
| The dedicated GitHub App name and id | `[[github-app]]`, and `[[human-policy]]` `github-app` |
| The Teleport issuer | `[[human-role]]` `issuer` |
| The Teleport application `uri` | `[[human-role]]` `audience` |
| The configured JWKS URL | `[[human-role]]` `jwks-url` |
| The human-route hostname | ingress and Teleport app registration |
| Load-test ceiling, latency change, duration, owner | running the harness above |

The GitHub App must be installed on the pilot repository **only**, with **`contents: read`** only.
`SwigApp` must not be reused.

## Teleport role template

Not a working role — the names marked `<...>` are the inputs above.

```yaml
kind: role
version: v7
metadata:
  name: <role-name-that-identifies-the-repository>
spec:
  options:
    max_session_ttl: 1h
  allow:
    request:
      roles: ["<role-name-that-identifies-the-repository>"]
      max_duration: 1h
      thresholds:
        - approve: 1
          deny: 1
    app_labels:
      name: ["<the idcat human app>"]
```

The role name shown in the request must identify the repository, so an approver can see what they
are approving without reading the free-text reason.

Configure **only the source-owning team's reviewer role** to approve it. Keep the free-text reason
for context, but never use it as an enforcement input — nothing in idcat reads it.

Require the same code-owner team to review later changes to this role, to the matching
`[[human-policy]]`, and to any expansion of the App installation.

## What an operator can reconstruct afterwards

Send both idcat issuance events and Teleport request events to Sentinel. Joining them gives:
who asked, which approval authorised it, which repository, which permissions, when it expired.

GitHub's own record is App-level. It shows that the App minted a token; it cannot show which person
used it. It is evidence about the App, not about a person, and must not be described as the latter.
