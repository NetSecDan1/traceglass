# Architecture and evidence contract

Traceglass uses one deterministic analysis engine for the CLI and HTML interface. The runtime is Node.js 22+ with ECMAScript modules. Demo, import, analysis, exports, and KQL generation use Node's standard library. Live authentication loads `@azure/identity` only when required.

## Components

| Component | Responsibility |
| --- | --- |
| `src/core/normalize.js` | Normalize Graph, Log Analytics and evidence exports; preserve unknowns and original observations |
| `src/core/analyze.js` | Produce summaries, evidence-linked findings, event associations, policy counts and sample-relative spike candidates |
| `src/core/kql.js` | Validate query specifications, generate KQL and apply supported predicates to local evidence |
| `src/connectors/` | Explicit credential selection and bounded read requests to Microsoft APIs |
| `src/workspace.js` | Load, scope and collect investigation datasets with provenance and collection warnings |
| `src/report.js` | JSON evidence bundles, integrity digest and Markdown incident reports |
| `src/cli.js` | Terminal entry point and structured command output |
| `src/server.js` | Loopback HTTP API, in-memory workspace and static assets |
| `web/` | Local HTML/CSS/JavaScript investigation and hunting interface |

The data path is **source records → normalization → scoped analysis → view/export**. Both interfaces call the same engine. The browser obtains normalized evidence and findings from the local API; it does not receive Microsoft bearer tokens or make direct cloud requests.

## Canonical events

An event carries its source event ID, UTC timestamp, user, application, resource, IP, sign-in type, overall error code, CA status, per-policy results, correlation/original-request/session identifiers, device information, location, risk, authentication details, source, and original `raw` record.

Unknown is a first-class state. Missing error codes do not become zero. Missing interaction type is not assumed interactive. A missing policy collection differs from an explicitly empty collection. Timestamps without an explicit timezone cannot support chronological claims. Graph dynamic objects and Log Analytics JSON-encoded strings normalize to the same shapes.

Repeated observations with the same event ID, event time, and identity count once. Richer policy evidence can complement a record with missing details. Conflicting outcome observations retain their original revisions in `observations`, set `observationConflict`, and keep the canonical outcome unknown. Do not discard these revisions when building future persistence or export formats.

Normalization prefers `CreatedDateTime` over `TimeGenerated`; the latter can reflect publication to Log Analytics. Query bounds and remote API timespans can further constrain coverage. [Microsoft timing explanation](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-interactive-sign-ins).

## Findings are evidence statements

The analyzer distinguishes:

- Failed sign-in plus enforced CA failure: enforcement observed.
- Sign-in failure with CA success/not applied: investigate another recorded failure cause.
- Report-only failure: simulated outcome; no denial attributed to that policy.
- Missing policy details: incomplete policy-level evidence.
- Contradictory observations: unresolved evidence conflict.
- Recent interactive success followed by background failure: comparison opportunity, with an explicit causality limit.

No rule certifies “working as designed.” That conclusion requires approved requirements and the applicable historical policy configuration, exclusions, authentication context, and supporting telemetry. Microsoft recommends examining the actual sign-in details and policy results when troubleshooting outcomes. [Conditional Access troubleshooting](https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-conditional-access).

## Event associations

The engine uses shared original-request, correlation, and session identifiers within the same identity to build stronger associations. It can also associate an original request with a prior event ID. These are labeled associations, not proven token exchanges.

Context-only links require the same known user and application and a preceding interactive event within 30 minutes. Unknown application placeholders never establish a match. Cross-user records are not linked merely because an identifier matches. Correlation IDs originate with clients and are not guaranteed accurate; authentication records can also be updated or aggregated. [Microsoft sign-in detail considerations](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details).

## Spike semantics

Local analysis groups observed events into five-minute buckets. A candidate needs at least 20 prior records, at least five current records, at least three CA failures, and a current failure rate above both 20% and three times the preceding sample's rate. Only observed buckets are counted; an empty interval is not evidence of successful operation.

The KQL spike preset compares the latest hour against the preceding portion of the selected window, with the same minimum-volume/rate safeguards. This is a triage heuristic, not seasonality-aware anomaly detection. A small user-filtered or capped sample is not a tenant-wide baseline.

## Query safety and execution

Query specifications contain allowlisted fields/operators, bounded hours/rows, validated IP/CIDR values, and validated grouping columns. String literals escape enclosing quotes, backslashes, and control characters. Table projections normalize dynamic/string differences **before** unioning the two sign-in tables, avoiding type-suffixed column loss. [Kusto string literal rules](https://learn.microsoft.com/en-us/kusto/query/scalar-data-types/string), [union behavior](https://learn.microsoft.com/en-us/kusto/query/union-operator).

The browser submits a specification, not executable KQL. The server compiles it. Local preview executes only the supported predicates; aggregation and Kusto evaluation require Log Analytics. The connector itself is a trusted internal API and must not be exposed as an arbitrary-query service.

## Trust and persistence boundaries

The HTTP server binds to loopback, validates Host/Origin, rejects cross-site requests, and requires a session token for POST operations. It serves a fixed asset allowlist with a content security policy. Uploaded JSON is data, not code. These controls reduce browser-to-localhost abuse; they do not authenticate other local processes or provide multi-user isolation.

Evidence is held in process memory until an analyst explicitly exports it. There is no durable case database or server-side user directory. Restarting clears the loaded dataset and returns to the synthetic case. Exports may contain highly sensitive identity data. Their SHA-256 digest detects changes to the serialized investigation; it is not a source signature, trusted timestamp, or chain-of-custody attestation.

See [CONNECTORS.md](CONNECTORS.md) for credential modes, permission requirements, request limits, Graph beta coverage and partial-response behavior, and [SECURITY.md](../SECURITY.md) for deployment boundaries.
