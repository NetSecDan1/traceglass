# Contributing

Use Node.js 22 or later. Demo and offline development work without installed dependencies; `npm ci` installs the pinned Azure Identity dependency for live authentication.

```powershell
npm ci
npm test
npm run check
npm start
```

The project uses plain ECMAScript modules and Node's built-in test runner. There is no frontend compilation step. Open `traceglass.code-workspace` for terminal tasks and debugger configurations.

## Changes we can evaluate

Describe the analyst problem, the resulting behavior, and the evidence that the change is correct. Keep source handling, normalization, deterministic analysis, and presentation separate. Preserve parity between terminal and browser investigation behavior.

For forensic logic or connector changes, add focused regression tests for meaningful failure cases: unknown or malformed values, partial collection, report-only policies, conflicting observations, identifier collisions, permission omissions, and time boundaries. Use mocked Microsoft responses. Do not make tests depend on an actual tenant or on secrets in CI.

Generated KQL must use validated specifications, explicit bounds, safe literals, and both user sign-in categories where applicable. Record which queries were actually executed against a test workspace; a syntax inspection is not live validation. Link official Microsoft documentation for any newly encoded service semantics.

## Synthetic evidence only

Use `example.com` identities and documentation IP ranges such as `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`. Do not paste real incident records into issues, pull requests, fixtures, screenshots or commit messages. The demo can be regenerated with `node fixtures/generate-demo.js`.

Keep imports and generated case outputs under ignored `data/` and `exports/`. Inspect `git diff --cached` and `git ls-files` before pushing. See [SECURITY.md](SECURITY.md) for private disclosure and repository hygiene.

## Review expectations

- Findings distinguish observation from inference and cite the events that support them.
- Missing evidence never silently becomes a success or “no policy applied.”
- UI controls have useful labels and keyboard access; dynamic content is escaped before rendering.
- Credentials, raw provider error bodies and access tokens never enter browser responses or logs.
- Documentation describes the implementation that exists and labels future work explicitly.
- Run the existing test suite and syntax checks, plus relevant manual UI or connector validation.

Contributions are provided under the repository's [MIT license](LICENSE).
