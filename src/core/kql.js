import { isIP } from 'node:net';

export const FILTER_FIELDS = Object.freeze([
  'UserPrincipalName',
  'UserId',
  'IPAddress',
  'AppDisplayName',
  'AppId',
  'ResourceDisplayName',
  'ConditionalAccessStatus',
  'ResultType',
  'RiskLevelDuringSignIn',
  'RiskState',
  'IsInteractive',
  'CorrelationId',
  'ClientAppUsed',
]);
export const FILTER_OPERATORS = Object.freeze([
  'eq',
  'neq',
  'contains',
  'startsWith',
  'in',
  'cidr',
]);
const PRESETS = ['user', 'risky', 'ip', 'caFailures', 'spikes', 'patterns'];
const MODES = ['events', 'distinct', 'patterns'];
const quote = (value) =>
  `'${String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\r/g, '\\r').replace(/\n/g, '\\n').replace(/\t/g, '\\t')}'`;
const bounded = (value, fallback, min, max, name) => {
  const n = value == null || value === '' ? fallback : Number(value);
  if (!Number.isInteger(n) || n < min || n > max)
    throw new TypeError(`${name} must be an integer from ${min} to ${max}.`);
  return n;
};

export function validateCidr(value) {
  if (typeof value !== 'string') throw new TypeError('CIDR must be a string.');
  const parts = value.trim().split('/');
  const family = isIP(parts[0]);
  if (
    !family ||
    parts[0].includes('%') ||
    parts.length !== 2 ||
    !/^\d{1,3}$/.test(parts[1]) ||
    Number(parts[1]) > (family === 4 ? 32 : 128)
  )
    throw new TypeError('Enter a valid IPv4 or IPv6 CIDR range.');
  return { value: `${parts[0]}/${Number(parts[1])}`, family };
}

function filterExpression(filter) {
  if (!filter || !FILTER_FIELDS.includes(filter.field))
    throw new TypeError(`Unsupported query field: ${filter?.field ?? '(missing)'}`);
  if (!FILTER_OPERATORS.includes(filter.operator))
    throw new TypeError(`Unsupported filter operator: ${filter.operator}`);
  const { field, operator, value } = filter;
  if (value === undefined || value === null || value === '')
    throw new TypeError(`A value is required for ${field}.`);
  if (operator === 'cidr') {
    if (field !== 'IPAddress')
      throw new TypeError('CIDR matching is supported only for IPAddress.');
    const range = validateCidr(value);
    return `${range.family === 4 ? 'ipv4_is_in_range' : 'ipv6_is_in_range'}(IPAddress, ${quote(range.value)})`;
  }
  if (field === 'IsInteractive') {
    if (!['eq', 'neq'].includes(operator) || ![true, false, 'true', 'false'].includes(value))
      throw new TypeError('IsInteractive requires eq or neq and a true/false value.');
    return `${field} ${operator === 'eq' ? '==' : '!='} ${String(value)}`;
  }
  if (operator === 'in') {
    const values = Array.isArray(value)
      ? value
      : String(value)
          .split(',')
          .map((item) => item.trim())
          .filter(Boolean);
    if (
      !values.length ||
      values.length > 100 ||
      values.some((item) => typeof item !== 'string' && typeof item !== 'number')
    )
      throw new TypeError('An in filter requires 1–100 scalar values.');
    return `${field} in~ (${values.map(quote).join(', ')})`;
  }
  if (typeof value !== 'string' && typeof value !== 'number')
    throw new TypeError('Filter values must be text or numbers.');
  return `${field} ${{ eq: '=~', neq: '!~', contains: 'contains', startsWith: 'startswith' }[operator]} ${quote(value)}`;
}

function absoluteRange(spec) {
  if (!spec.start && !spec.end) return null;
  if (!spec.start || !spec.end)
    throw new TypeError('Provide both start and end for an absolute time range.');
  const valid = (value) =>
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value) &&
    Number.isFinite(Date.parse(value));
  if (!valid(spec.start) || !valid(spec.end))
    throw new TypeError('start and end must be ISO timestamps with an explicit timezone.');
  const start = Date.parse(spec.start),
    end = Date.parse(spec.end);
  if (start >= end || end - start > 90 * 86400000)
    throw new TypeError('The time range must be increasing and no longer than 90 days.');
  return { start: new Date(start).toISOString(), end: new Date(end).toISOString() };
}

function tableLeg(table, hours, range) {
  const stringFields = [
    'Id',
    'UserPrincipalName',
    'UserDisplayName',
    'UserId',
    'AppDisplayName',
    'AppId',
    'ResourceDisplayName',
    'IPAddress',
    'ResultType',
    'ResultDescription',
    'ConditionalAccessStatus',
    'CorrelationId',
    'OriginalRequestId',
    'SessionId',
    'RiskLevelDuringSignIn',
    'RiskLevelAggregated',
    'RiskState',
    'ClientAppUsed',
    'AuthenticationRequirement',
    'Location',
  ];
  const dynamicFields = [
    'ConditionalAccessPolicies',
    'DeviceDetail',
    'LocationDetails',
    'AuthenticationDetails',
    'Status',
    'SignInEventTypes',
  ];
  const timeFilter = range
    ? `coalesce(todatetime(column_ifexists("CreatedDateTime", TimeGenerated)), TimeGenerated) between (datetime(${range.start}) .. datetime(${range.end}))`
    : `coalesce(todatetime(column_ifexists("CreatedDateTime", TimeGenerated)), TimeGenerated) >= ago(${hours}h)`;
  return `(${table}\n    | where ${timeFilter}\n    | project TimeGenerated, CreatedDateTime = coalesce(todatetime(column_ifexists("CreatedDateTime", TimeGenerated)), TimeGenerated),\n        SourceTable = ${quote(table)}, IsInteractive = tobool(column_ifexists("IsInteractive", ${table === 'AADNonInteractiveUserSignInLogs' ? 'false' : 'bool(null)'})),\n        ${stringFields.map((field) => `${field} = tostring(column_ifexists("${field}", ""))`).join(',\n        ')},\n        ${dynamicFields.map((field) => `${field} = parse_json(tostring(column_ifexists("${field}", "")))`).join(',\n        ')})`;
}

/** Compile an allowlisted investigation specification to portable read-only Azure Monitor KQL. */
export function buildKql(spec = {}) {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec))
    throw new TypeError('Query specification must be an object.');
  const preset = spec.preset ?? 'user',
    mode = spec.mode ?? (preset === 'patterns' ? 'patterns' : 'events');
  if (!PRESETS.includes(preset)) throw new TypeError(`Unsupported preset: ${preset}`);
  if (!MODES.includes(mode)) throw new TypeError(`Unsupported result mode: ${mode}`);
  const hours = bounded(spec.hours, 24, 1, 2160, 'hours'),
    limit = bounded(spec.limit, 1000, 1, 10000, 'limit');
  const range = absoluteRange(spec);
  if (spec.filters != null && !Array.isArray(spec.filters))
    throw new TypeError('filters must be an array.');
  if ((spec.filters?.length ?? 0) > 30) throw new TypeError('Use at most 30 query filters.');
  const filters = [...(spec.filters ?? [])];
  if (spec.user) filters.push({ field: 'UserPrincipalName', operator: 'eq', value: spec.user });
  if (spec.ip) {
    if (!isIP(String(spec.ip)) || String(spec.ip).includes('%'))
      throw new TypeError('Enter a valid IPv4 or IPv6 address.');
    filters.push({ field: 'IPAddress', operator: 'eq', value: spec.ip });
  }
  if (spec.cidr) filters.push({ field: 'IPAddress', operator: 'cidr', value: spec.cidr });
  if (preset === 'risky')
    filters.push({
      field: 'RiskLevelDuringSignIn',
      operator: 'in',
      value: ['low', 'medium', 'high'],
    });
  if (preset === 'caFailures')
    filters.push({ field: 'ConditionalAccessStatus', operator: 'eq', value: 'failure' });
  const expressions = filters.map(filterExpression);
  const warning = [
    'Both user sign-in tables must be collected. A missing table may return a partial result with an Azure Monitor warning; inspect query diagnostics.',
    'Time filtering uses CreatedDateTime, falling back to TimeGenerated when absent. Ingestion timestamp constraints applied by a remote API can still omit late-arriving records.',
  ];
  if (!spec.user && preset === 'user' && !filters.length)
    warning.push('No user selected: this query covers all users in the requested time range.');
  if (preset === 'ip' && !spec.ip && !spec.cidr && !filters.some((f) => f.field === 'IPAddress'))
    warning.push('No address selected: add an IP address or CIDR filter to narrow this hunt.');
  let query = `// Traceglass: interactive + non-interactive user sign-ins. Read-only.\n// Normalize dynamic/string columns before union to prevent suffixed column loss.\nunion isfuzzy=true\n${tableLeg('SigninLogs', hours, range)},\n${tableLeg('AADNonInteractiveUserSignInLogs', hours, range)}`;
  for (const expression of expressions) query += `\n| where ${expression}`;
  let description = `${preset} hunt across both sign-in tables over ${hours} hours`;
  const groupBy = spec.groupBy ?? ['UserPrincipalName', 'AppDisplayName', 'IPAddress'];
  if (
    !Array.isArray(groupBy) ||
    !groupBy.length ||
    groupBy.length > 6 ||
    groupBy.some((field) => !FILTER_FIELDS.includes(field))
  )
    throw new TypeError('groupBy must contain 1–6 supported query fields.');
  const grouping = [...new Set(groupBy)].join(', ');
  if (preset === 'spikes') {
    if (hours < 2)
      throw new TypeError('Spike hunting requires at least 2 hours for a prior comparison window.');
    const pivot = range
      ? `datetime(${new Date(Date.parse(range.end) - 3600000).toISOString()})`
      : 'ago(1h)';
    if (range && Date.parse(range.end) - Date.parse(range.start) < 7200000)
      throw new TypeError('Spike hunting requires at least 2 hours for a prior comparison window.');
    query = `let Observed =\n${query};\nlet Baseline = toscalar(Observed | where CreatedDateTime < ${pivot} | summarize Rate = todouble(countif(ConditionalAccessStatus =~ 'failure')) / count() | project Rate);\nlet BaselineCount = toscalar(Observed | where CreatedDateTime < ${pivot} | count);\nObserved\n| where CreatedDateTime >= ${pivot}\n| summarize Total = count(), CAFailures = countif(ConditionalAccessStatus =~ 'failure'), Users = dcount(UserPrincipalName) by bin(CreatedDateTime, 5m)\n| extend FailureRate = todouble(CAFailures) / Total, BaselineRate = Baseline, BaselineRecords = BaselineCount\n| extend IsSpike = BaselineRecords >= 20 and Total >= 5 and CAFailures >= 3 and FailureRate > max_of(0.2, 3.0 * BaselineRate)\n| order by CreatedDateTime asc\n| take ${limit}`;
    description =
      'Five-minute CA failure rates in the latest hour compared with preceding observations';
    warning.push(
      'This rate heuristic requires a representative baseline; it does not establish a policy change, attack, or service outage.',
    );
  } else if (mode === 'distinct') {
    query += `\n| summarize Events = count(), FirstSeen = min(CreatedDateTime), LastSeen = max(CreatedDateTime) by ${grouping}\n| order by Events desc\n| take ${limit}`;
    description += '; distinct combinations with occurrence counts';
  } else if (mode === 'patterns') {
    query += `\n| summarize Events = count(), Failures = countif(isnotempty(ResultType) and ResultType !in~ ('0', 'Success')), CAFailures = countif(ConditionalAccessStatus =~ 'failure'), DistinctUsers = dcount(UserPrincipalName) by ${[...new Set([...groupBy, 'IsInteractive'])].join(', ')}, bin(CreatedDateTime, 15m)\n| order by CAFailures desc, Events desc\n| take ${limit}`;
    description += '; repeating combinations in 15-minute windows';
  } else query += `\n| order by CreatedDateTime asc\n| take ${limit}`;
  warning.push(`Output is capped at ${limit} rows; reaching the cap can make evidence incomplete.`);
  return { query, description, warnings: warning };
}

const LOCAL_FIELDS = {
  UserPrincipalName: (e) => e.userPrincipalName,
  UserId: (e) => e.userId,
  IPAddress: (e) => e.ipAddress,
  AppDisplayName: (e) => e.appDisplayName,
  AppId: (e) => e.appId,
  ResourceDisplayName: (e) => e.resourceDisplayName,
  ConditionalAccessStatus: (e) => e.conditionalAccessStatus,
  ResultType: (e) => (e.status.errorCode === null ? '' : String(e.status.errorCode)),
  RiskLevelDuringSignIn: (e) => e.riskLevel,
  RiskState: (e) => e.riskState,
  IsInteractive: (e) => e.isInteractive,
  CorrelationId: (e) => e.correlationId,
  ClientAppUsed: (e) => e.clientAppUsed,
};

function addressNumber(address, family) {
  if (isIP(address) === 4) {
    const v4 = address.split('.').reduce((n, part) => (n << 8n) + BigInt(part), 0n);
    return family === 6 ? (0xffffn << 32n) + v4 : v4;
  }
  if (isIP(address) !== 6 || family !== 6) return null;
  let source = address;
  if (source.includes('.')) {
    const index = source.lastIndexOf(':');
    const v4 = addressNumber(source.slice(index + 1), 4);
    source = `${source.slice(0, index)}:${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const halves = source.split('::'),
    left = halves[0] ? halves[0].split(':') : [],
    right = halves[1] ? halves[1].split(':') : [];
  const parts =
    halves.length === 2
      ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
      : left;
  return parts.reduce((n, part) => (n << 16n) + BigInt(`0x${part}`), 0n);
}

function inRange(address, cidr) {
  const { value, family } = validateCidr(cidr),
    [network, prefix] = value.split('/');
  const number = addressNumber(address, family),
    base = addressNumber(network, family);
  if (number === null || base === null) return false;
  const shift = BigInt((family === 4 ? 32 : 128) - Number(prefix));
  return number >> shift === base >> shift;
}

/** Apply the same allowlisted predicates locally. Aggregation is a separate presentation step. */
export function filterEvents(events, spec = {}) {
  buildKql(spec); // Keep validation identical to the live-query compiler.
  const range = absoluteRange(spec),
    filters = [...(spec.filters ?? [])];
  if (spec.user) filters.push({ field: 'UserPrincipalName', operator: 'eq', value: spec.user });
  if (spec.ip) filters.push({ field: 'IPAddress', operator: 'eq', value: spec.ip });
  if (spec.cidr) filters.push({ field: 'IPAddress', operator: 'cidr', value: spec.cidr });
  if (spec.preset === 'risky')
    filters.push({
      field: 'RiskLevelDuringSignIn',
      operator: 'in',
      value: ['low', 'medium', 'high'],
    });
  if (spec.preset === 'caFailures')
    filters.push({ field: 'ConditionalAccessStatus', operator: 'eq', value: 'failure' });
  return events
    .filter((event) => {
      if (
        range &&
        (!event.timestamp || event.timestamp < range.start || event.timestamp > range.end)
      )
        return false;
      return filters.every(({ field, operator, value }) => {
        const original = LOCAL_FIELDS[field](event),
          actual = String(original ?? '').toLowerCase(),
          expected = String(value).toLowerCase();
        if (field === 'IsInteractive' && original === null) return false;
        if (operator === 'cidr') return inRange(String(original ?? ''), String(value));
        if (operator === 'in')
          return (
            Array.isArray(value)
              ? value
              : String(value)
                  .split(',')
                  .map((x) => x.trim())
          ).some((x) => actual === String(x).toLowerCase());
        if (operator === 'eq') return actual === expected;
        if (operator === 'neq') return actual !== expected;
        if (operator === 'contains') return actual.includes(expected);
        return actual.startsWith(expected);
      });
    })
    .slice(0, Number(spec.limit ?? 1000));
}
