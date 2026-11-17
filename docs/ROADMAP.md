# Roadmap

Traceglass v0.1 supplies the local investigation engine, HTML/terminal workflows, evidence exports, read connectors, and a structured KQL builder. The following work is proposed; it is not implemented functionality or a delivery commitment.

## 1. Validate the investigation foundation

- Run an authorized test-tenant matrix covering delegated and app access, missing CA permissions, retention boundaries, Graph pagination, and both workspace tables.
- Execute every generated KQL preset against supported schemas and capture versioned, sanitized regression cases.
- Add historical CA policy snapshots and audit-change correlation so “recorded enforcement” can be compared with the configuration at event time.
- Add richer authentication-step, session-lifetime, continuous-access-evaluation, and device-state comparison without inventing token lineage.
- Provide signed case manifests and an explicit evidence intake/verification workflow.

## 2. Build an enterprise service boundary

- Separate the analyst interface from a durable, tenant-isolated collection service.
- Add organization SSO, role-based permissions, case ownership, audit logging, encryption, retention controls, and reviewed export policies.
- Introduce bounded collection jobs, cancellation, scheduling, queue backpressure, and operational health metrics.
- Build tenant-wide baselines from a complete, documented collection process; add seasonality and volume-aware detectors.
- Establish supported Microsoft API versions, cloud endpoints, dependency maintenance, accessibility review, security testing, and operational runbooks.

Do not deploy the current loopback server behind a public reverse proxy as a substitute for these boundaries.

## 3. Add a governed agent layer

The existing deterministic functions are useful tool boundaries for a future assistant: search authorized evidence, compile a query specification, collect a bounded window, explain recorded policy results, and draft a cited case narrative.

An agent integration should retain these rules:

- Tool access follows the analyst's tenant, role and case scope; model text never becomes unrestricted KQL or shell execution.
- Every factual explanation points to event IDs and preserved observations; the model does not turn an association into a causal claim.
- Sensitive fields are minimized or redacted under an explicit organizational data policy before model access.
- Prompt-injection defenses treat imported logs, names, descriptions and query results as untrusted data.
- Read actions, persistent writes, outbound sharing and policy remediation have separate capabilities and approval boundaries.
- The deterministic engine remains usable and testable without an AI provider.
- Evaluation covers missing evidence, conflicting records, misleading policy names, adversarial inputs, and unsupported certainty.

There is currently **no model provider, LLM call, autonomous backend, or agent-driven UI control**. A future agent should improve evidence navigation and explanation while leaving authorization and factual checks in the application.
