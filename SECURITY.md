# Security policy and deployment boundary

Traceglass v0.1 is a local, single-analyst investigation tool. It is not an authenticated multi-user service, an enterprise security control, or a production-certified incident platform. Keep the server on its default loopback interface. Do not expose it through a public tunnel or reverse proxy.

## Data and credentials

- Real sign-in records contain identifiers, IP addresses, device details, locations, policy information and authentication context. Treat imports, raw observations and exports as sensitive incident evidence.
- Evidence is retained in memory during the process lifetime. Explicit exports write files under the analyst's control. Operating system access controls, backups and disk encryption remain the operator's responsibility.
- The backend uses an explicitly selected Azure credential. Microsoft access tokens and configured client secrets are not passed to the HTML interface. Traceglass does not persist its own token cache; Azure CLI manages its existing cache outside the app.
- Use approved read-only permissions, an appropriate analyst role, and table/workspace scoping. Do not grant policy write permissions for analysis. Configuration and consent are described in [CONNECTORS.md](docs/CONNECTORS.md).
- No AI service receives evidence in this version. There is no telemetry or analytics integration in the application.

## Local HTTP protections

The server validates Host and Origin, rejects cross-site requests, requires a session token for mutations, uses a fixed static-asset allowlist, applies a content security policy, and limits request bodies. Those controls reduce cross-site access to localhost. **They do not protect against another process running as the analyst or another local user with access to the port.** Browser extensions and endpoint compromise remain outside this boundary.

Cloud requests are bounded and read-only. Graph continuation links are restricted to the expected HTTPS endpoint, redirects are rejected, and provider errors are sanitized. UI queries are built from validated specifications. The internal Log Analytics connector is not a security sandbox for arbitrary untrusted query strings.

## Interpretation and evidence integrity

Incomplete collections, omitted policy fields, report-only results, unknown statuses, and conflicting observations must remain visible. Do not use an automated finding as the sole basis for disabling a control or concluding that a policy matched intended requirements.

JSON exports include a SHA-256 digest of the serialized investigation. This can detect modification relative to a preserved digest. It does not authenticate Microsoft as the source, prove completeness, establish a trusted timestamp, or replace your organization's chain-of-custody process.

## Publishing safely

Keep real data under ignored `data/` or `exports/`, and secrets in ignored environment configuration or an approved secret manager. Commit only synthetic fixtures. The repository ignores common credential files, populated environment files, authentication captures, logs and local artifacts; Git ignore rules are not a data-loss-prevention system.

Before pushing a public branch, inspect the staged diff and tracked file list. Remove accidental sensitive content from the Git history before publication. If a credential has been exposed, revoke or rotate it; deleting a file from the latest commit is insufficient.

## Reporting a vulnerability

Do not open a public issue containing tenant records, tokens, app secrets, exploitable private endpoint details, or unredacted screenshots. Use the repository's private vulnerability reporting channel if enabled. If no private channel is available, open a content-free issue requesting a private contact method before sharing details.

Include the affected version, impact, a minimal synthetic reproduction, and any suggested mitigation. There is no guaranteed response SLA for this initial release. Report vulnerabilities in Microsoft services or SDKs through the relevant vendor's disclosure process.
