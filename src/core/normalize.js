import { createHash } from 'node:crypto';

const text = (value, fallback = '') => (value == null ? fallback : String(value));
const first = (...values) =>
  values.find((value) => value !== undefined && value !== null && value !== '');
const parse = (value) => {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
};
const object = (value) => {
  const parsed = parse(value);
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
};
const array = (value) => {
  const parsed = parse(value);
  return Array.isArray(parsed) ? parsed : [];
};
const boolean = (value) =>
  value === true || (typeof value === 'string' && value.toLowerCase() === 'true')
    ? true
    : value === false || (typeof value === 'string' && value.toLowerCase() === 'false')
      ? false
      : null;
const number = (value) => {
  if (typeof value !== 'number' && !(typeof value === 'string' && /^\d+$/.test(value.trim())))
    return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
};
const date = (value) => {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value))
    return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
};

function rowsFrom(input) {
  if (Array.isArray(input)) return input;
  if (!input || typeof input !== 'object')
    throw new TypeError(
      'Expected sign-in records, a Graph value envelope, or a Log Analytics response.',
    );
  if (Array.isArray(input.value)) return input.value;
  if (Array.isArray(input.events)) return input.events;
  if (Array.isArray(input.records)) return input.records;
  if (Array.isArray(input.tables))
    return input.tables
      .filter(
        (table) => table.name !== 'QueryStatus' && table.name !== 'QueryCompletionInformation',
      )
      .flatMap((table) => {
        if (!Array.isArray(table.columns) || !Array.isArray(table.rows)) return [];
        return table.rows.map((row) =>
          Object.fromEntries(table.columns.map((column, index) => [column.name, row[index]])),
        );
      });
  if (first(input.id, input.Id, input.createdDateTime, input.TimeGenerated)) return [input];
  throw new TypeError('No supported sign-in record collection was found.');
}

function normalizePolicy(policy) {
  const p = object(policy);
  return {
    id: text(first(p.id, p.Id)),
    displayName: text(first(p.displayName, p.DisplayName), 'Unnamed policy'),
    result: text(first(p.result, p.Result), 'unknown'),
    enforcedGrantControls: array(first(p.enforcedGrantControls, p.EnforcedGrantControls)).map(
      String,
    ),
    enforcedSessionControls: array(first(p.enforcedSessionControls, p.EnforcedSessionControls)).map(
      String,
    ),
    conditionsSatisfied: first(p.conditionsSatisfied, p.ConditionsSatisfied, null),
    conditionsNotSatisfied: first(p.conditionsNotSatisfied, p.ConditionsNotSatisfied, null),
  };
}

/** Normalize Graph, Azure Monitor, or an already-normalized evidence export. No missing values are treated as success. */
export function normalizeEvents(input, { source } = {}) {
  const events = rowsFrom(input).map((r, index) => {
    if (!r || typeof r !== 'object' || Array.isArray(r))
      throw new TypeError(`Record ${index + 1} is not an object.`);
    const status = object(first(r.status, r.Status));
    const device = object(
      first(
        r.device,
        r.deviceDetail,
        r.DeviceDetail,
        r.DeviceDetail_dynamic,
        r.DeviceDetail_string,
      ),
    );
    const location = object(
      first(r.location, r.LocationDetails, r.LocationDetails_dynamic, r.LocationDetails_string),
    );
    const types = array(first(r.signInEventTypes, r.SignInEventTypes));
    const sourceTable = text(first(r.SourceTable, r.Type, source, r.source));
    let isInteractive = boolean(first(r.isInteractive, r.IsInteractive));
    if (isInteractive === null) {
      if (
        types.includes('nonInteractiveUser') ||
        types.includes('refreshToken') ||
        sourceTable.endsWith('AADNonInteractiveUserSignInLogs')
      )
        isInteractive = false;
      else if (types.includes('interactiveUser') || types.includes('interactive'))
        isInteractive = true;
    }
    const policyInput = first(
      r.policies,
      r.appliedConditionalAccessPolicies,
      r.ConditionalAccessPolicies,
      r.ConditionalAccessPolicies_dynamic,
      r.ConditionalAccessPolicies_string,
      r.AppliedConditionalAccessPolicies,
    );
    const policyData = parse(policyInput);
    const policyVisibility =
      r.policyVisibility === 'missing'
        ? 'missing'
        : Array.isArray(policyData)
          ? 'available'
          : 'missing';
    const resultType = first(r.ResultType, r.ResultSignature);
    const errorCode = number(
      first(
        status.errorCode,
        status.ErrorCode,
        resultType === 'Success' ? 0 : number(resultType),
        number(r.ResultSignature),
      ),
    );
    const ca = text(first(r.conditionalAccessStatus, r.ConditionalAccessStatus), 'unknown');
    return {
      id: text(
        first(r.id, r.Id),
        `import-${createHash('sha256').update(JSON.stringify(r)).digest('hex').slice(0, 24)}`,
      ),
      timestamp: date(first(r.timestamp, r.createdDateTime, r.CreatedDateTime, r.TimeGenerated)),
      userPrincipalName: text(first(r.userPrincipalName, r.UserPrincipalName)),
      userDisplayName: text(first(r.userDisplayName, r.UserDisplayName)),
      userId: text(first(r.userId, r.UserId)),
      appDisplayName: text(first(r.appDisplayName, r.AppDisplayName), 'Unknown application'),
      appId: text(first(r.appId, r.AppId)),
      resourceDisplayName: text(
        first(r.resourceDisplayName, r.ResourceDisplayName),
        'Unknown resource',
      ),
      ipAddress: text(first(r.ipAddress, r.IPAddress)),
      isInteractive,
      signInEventTypes: types,
      status: {
        errorCode,
        failureReason: text(first(status.failureReason, status.FailureReason, r.ResultDescription)),
        additionalDetails: text(first(status.additionalDetails, status.AdditionalDetails)),
      },
      conditionalAccessStatus: { 0: 'success', 1: 'failure', 2: 'notApplied' }[ca] ?? ca,
      policies: array(policyInput).map(normalizePolicy),
      policyVisibility,
      correlationId: text(first(r.correlationId, r.CorrelationId)),
      originalRequestId: text(first(r.originalRequestId, r.OriginalRequestId)),
      sessionId: text(first(r.sessionId, r.SessionId)),
      device: {
        id: text(first(device.id, device.deviceId)),
        displayName: text(device.displayName),
        operatingSystem: text(device.operatingSystem),
        browser: text(device.browser),
        isCompliant: boolean(device.isCompliant),
        isManaged: boolean(device.isManaged),
        trustType: text(device.trustType),
      },
      location: {
        city: text(location.city),
        countryOrRegion: text(
          first(location.countryOrRegion, typeof r.Location === 'string' ? r.Location : undefined),
        ),
      },
      riskLevel: text(
        first(
          r.riskLevel,
          r.riskLevelDuringSignIn,
          r.RiskLevelDuringSignIn,
          r.riskLevelAggregated,
          r.RiskLevelAggregated,
        ),
        'unknown',
      ),
      riskState: text(first(r.riskState, r.RiskState), 'unknown'),
      authenticationDetails: array(
        first(
          r.authenticationDetails,
          r.AuthenticationDetails,
          r.AuthenticationDetails_dynamic,
          r.AuthenticationDetails_string,
        ),
      ),
      clientAppUsed: text(first(r.clientAppUsed, r.ClientAppUsed)),
      authenticationRequirement: text(
        first(r.authenticationRequirement, r.AuthenticationRequirement),
      ),
      source: text(first(source, r.source, r.SourceTable, r.Type), 'import'),
      raw: r.raw ?? r,
      ...(Array.isArray(r.observations) ? { observations: r.observations } : {}),
      ...(r.observationConflict === true ? { observationConflict: true } : {}),
    };
  });
  // Count a repeated event once, while retaining different raw observations. Contradictory outcomes remain unknown.
  const unique = new Map();
  for (const event of events) {
    const key = `${event.id}|${event.timestamp ?? ''}|${event.userId || event.userPrincipalName.toLowerCase()}`;
    const existing = unique.get(key);
    if (!existing) {
      unique.set(key, event);
      continue;
    }
    const policyKey = (value) =>
      JSON.stringify(
        value.policies
          .map((p) => ({
            id: p.id || p.displayName,
            result: p.result,
            grants: [...p.enforcedGrantControls].sort(),
            sessions: [...p.enforcedSessionControls].sort(),
          }))
          .sort((a, b) => a.id.localeCompare(b.id)),
      );
    const conflict =
      existing.observationConflict ||
      event.observationConflict ||
      (existing.status.errorCode !== null &&
        event.status.errorCode !== null &&
        existing.status.errorCode !== event.status.errorCode) ||
      (existing.conditionalAccessStatus !== 'unknown' &&
        event.conditionalAccessStatus !== 'unknown' &&
        existing.conditionalAccessStatus !== event.conditionalAccessStatus) ||
      (existing.policyVisibility === 'available' &&
        event.policyVisibility === 'available' &&
        policyKey(existing) !== policyKey(event)) ||
      (existing.isInteractive !== null &&
        event.isInteractive !== null &&
        existing.isInteractive !== event.isInteractive);
    const chosen =
      existing.policyVisibility === 'missing' && event.policyVisibility === 'available'
        ? { ...event }
        : { ...existing };
    const observations = [
      ...(existing.observations ?? [{ source: existing.source, raw: existing.raw }]),
      ...(event.observations ?? [{ source: event.source, raw: event.raw }]),
    ];
    chosen.observations = [
      ...new Map(
        observations.map((observation) => [JSON.stringify(observation), observation]),
      ).values(),
    ];
    if (conflict) {
      chosen.observationConflict = true;
      chosen.status = {
        errorCode: null,
        failureReason: 'Conflicting observations of this event; inspect preserved raw revisions.',
        additionalDetails: '',
      };
      chosen.conditionalAccessStatus = 'unknown';
      chosen.policies = [];
      chosen.policyVisibility = 'missing';
    }
    unique.set(key, chosen);
  }
  return [...unique.values()].sort((a, b) =>
    (a.timestamp ?? '9999').localeCompare(b.timestamp ?? '9999'),
  );
}
