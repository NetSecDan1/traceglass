# Connecting Microsoft Entra and Log Analytics

Traceglass runs locally and reads Microsoft data through its Node backend. Its supported live endpoints are Azure Public Cloud only. Tenant credentials and access tokens are never sent to the HTML application. Importing a JSON export requires no Microsoft connection.

## Choose the data path

**Log Analytics / Microsoft Sentinel is the recommended production data path.** Enable both interactive and non-interactive user sign-in categories in Entra diagnostic settings and send them to the workspace. The query builder uses `SigninLogs` and `AADNonInteractiveUserSignInLogs`. A missing table, missing export configuration, retention, table permissions, or ingestion delay can leave an investigation incomplete. [Microsoft diagnostic export documentation](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-diagnostic-settings-logs-options).

The **Graph connector deliberately uses `/beta/auditLogs/signIns`** with an explicit filter for both `interactiveUser` and `nonInteractiveUser`. An unfiltered request can otherwise omit non-interactive events. Microsoft states that beta APIs are subject to change and unsupported for production applications. Traceglass exposes this limitation in every Graph collection result rather than implying stable complete coverage. The connector does not silently switch to a v1 endpoint that changes coverage. [Microsoft Graph sign-in API](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta).

Offline files remain useful when tenant access is unavailable or when preserving an incident snapshot. Export both sign-in categories and retain the original unmodified files with your incident record. Raw imports and exported evidence can contain personal and security information; keep them outside the public source repository.

## Authentication modes

Set configuration in the process environment, or in the project's ignored `.env` when using the provided start command. Do not paste credentials into the web interface. The selected credential is explicit; there is no fallback to a different signed-in account, secret, or managed identity.

| `TRACEGLASS_AUTH_MODE` | Use | Required settings |
| --- | --- | --- |
| `offline` | Demo and imported exports | None |
| `azure-cli` | Existing analyst Azure CLI login | Optional `TRACEGLASS_TENANT_ID` to select the tenant |
| `interactive-browser` | Analyst's own delegated access using an app registration and browser PKCE flow | `TRACEGLASS_TENANT_ID`, `TRACEGLASS_CLIENT_ID` |
| `device-code` | Delegated access with a visible device prompt | `TRACEGLASS_TENANT_ID`, `TRACEGLASS_CLIENT_ID` |
| `client-secret` | Application access | `TRACEGLASS_TENANT_ID`, `TRACEGLASS_CLIENT_ID`, `TRACEGLASS_CLIENT_SECRET` |
| `managed-identity` | Application access on an Azure host | Optional `TRACEGLASS_CLIENT_ID` for a user-assigned identity |

Set `TRACEGLASS_WORKSPACE_ID` to the Log Analytics workspace GUID for workspace queries. This is the workspace ID shown on its overview, not the subscription, tenant, workspace name, or ARM resource path.

For Azure CLI:

```powershell
az login --tenant YOUR-TENANT-ID
$env:TRACEGLASS_AUTH_MODE = 'azure-cli'
$env:TRACEGLASS_TENANT_ID = 'YOUR-TENANT-ID'
$env:TRACEGLASS_WORKSPACE_ID = 'YOUR-WORKSPACE-ID'
npm start
```

An Azure CLI login proves authentication only. The CLI application's consent and the analyst's roles might not permit Graph audit logs or Conditional Access details. If access is denied, configure your organization's dedicated public-client app with the required read permissions and choose `interactive-browser` or `device-code`.

For delegated app authentication, create a single-tenant public client. For `interactive-browser`, configure a **Mobile and desktop applications** redirect URI of `http://localhost`; the Node SDK opens a browser and uses authorization code flow with PKCE. For `device-code`, enable public-client flows if required by your registration and tenant policy. Device-code authentication can be blocked by Conditional Access: use the approved interactive method rather than weakening tenant policy. [Azure Identity browser credential](https://learn.microsoft.com/en-us/javascript/api/@azure/identity/interactivebrowsercredential?view=azure-node-latest), [device code credential](https://learn.microsoft.com/en-us/javascript/api/@azure/identity/devicecodecredential?view=azure-node-latest).

For app access, prefer an Azure managed identity when available. Grant the identity only the needed Graph application roles and workspace read access. A managed identity does not become authorized merely because it exists. Client secrets are supported for environments that require them; inject a short-lived secret using your organization's secret manager and rotate it. Traceglass does not write token caches to disk. Azure CLI manages its own existing account cache outside this app. [Microsoft explicit credential guidance](https://learn.microsoft.com/en-us/azure/developer/javascript/sdk/authentication/best-practices).

## Permissions and data visibility

For Graph, grant `AuditLog.Read.All` plus `Policy.Read.ConditionalAccess` (or an existing suitable read permission) with administrator consent. Use delegated permissions for analyst sign-in and application permissions for app or managed-identity access. Delegated access also requires an appropriate Entra role; **Security Reader** is a useful read-only role covering sign-in and CA visibility. Reports Reader alone does not provide all CA details. Traceglass never requires a policy write permission.

When CA permission is missing, Microsoft can omit `appliedConditionalAccessPolicies` even while returning the sign-in. That omission is **missing evidence**, not proof that no policy applied. [Microsoft Graph permission and role requirements](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta).

For Log Analytics, configure delegated `Data.Read` when using your own delegated app and give the analyst workspace/table query access. For application access, assign the service principal or managed identity an appropriate workspace read role; a custom role scoped to the two sign-in tables can reduce access. Validate table-level restrictions in your organization. The endpoint is `https://api.loganalytics.azure.com`, with the token scope `https://api.loganalytics.io/.default`. [API authentication](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api), [workspace access controls](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/manage-access).

## Collection and interpretation safeguards

- Each live request is bounded to at most 31 days. Graph defaults to 5,000 events, permits at most 50,000, and limits pagination. Limit stops are prominently marked as incomplete.
- Graph follows continuation links only on the HTTPS Graph sign-in endpoint. Tokens are never forwarded to another host or resource path, and HTTP redirects are rejected.
- HTTP throttling and transient failures get bounded retries. Short `Retry-After` values are honored; longer delays return a retry instruction to the analyst.
- Log Analytics can return HTTP 200 alongside `PartialError`. Traceglass preserves the rows but marks the result incomplete. Reaching a generated query's final row limit also marks completeness as uncertain. [Response format](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/response-format).
- Log Analytics query execution uses the query endpoint, not management APIs. The UI/server executes builder-generated queries; connector internals are not a security sandbox for arbitrary KQL supplied by untrusted code.
- Error messages omit raw provider response bodies and tokens. They identify authentication, access, throttling, timeout, and invalid-response failures without echoing credentials.
- A credential configuration status is not an authentication or authorization test. Access is established only when the actual Microsoft request succeeds.

Record timestamps and data availability matter. `CreatedDateTime` reflects event time; `TimeGenerated` can be the Log Analytics receipt/publication time. Supply explicit UTC `Z` or timezone offsets for investigation bounds. [Interactive sign-in semantics](https://learn.microsoft.com/entra/identity/monitoring-health/concept-interactive-sign-ins). Non-interactive portal rows may be grouped, and confidential-client IP fields can reflect the original token issuance location rather than the current refresh request origin. [Non-interactive sign-in semantics](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins).

Correlation IDs are supplied by clients, and Microsoft does not guarantee their accuracy. A shared-identifier link is stronger than temporal proximity, but does not prove token lineage or malicious intent. MFA attempts can produce multiple Azure Monitor records while the portal shows a single entry, and authentication details can be incomplete before aggregation finishes. Preserve source observations when investigating conflicting outcomes. [Sign-in detail considerations](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details).

Graph retention follows tenant licensing and Microsoft retention limits; requesting a larger interval does not recover expired events. Workspace retention is separate. [Microsoft retention reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention).

## Verification status

Connector tests use mocked Microsoft responses to validate event-type filtering, OData escaping, pagination, next-link isolation, incomplete-result flags, retry limits, credential selection, and secret-free status/errors. A real tenant connection still needs validation with your organization's registration, consent, roles, diagnostic exports, and Conditional Access configuration.
