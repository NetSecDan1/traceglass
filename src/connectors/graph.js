import { SCOPES } from './auth.js';
import { ConnectorError, requestJson, trustedUrl } from './http.js';

export function validateTimeRange(start, end) {
  const explicitZone = (value) =>
    typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value);
  if (!explicitZone(start) || !explicitZone(end))
    throw new Error('Supply ISO start and end timestamps with an explicit timezone (Z or offset).');
  const from = new Date(start);
  const to = new Date(end);
  if (
    !start ||
    !end ||
    !Number.isFinite(from.getTime()) ||
    !Number.isFinite(to.getTime()) ||
    from >= to
  )
    throw new Error('Supply valid start and end timestamps with start before end.');
  if (to - from > 31 * 86400000)
    throw new Error('A live Graph investigation is limited to 31 days per request.');
  return { start: from.toISOString(), end: to.toISOString() };
}

export async function fetchGraphSignIns({
  user = '',
  start,
  end,
  maxEvents = 5000,
  credential,
  apiVersion = 'beta',
  fetchImpl,
  sleepImpl,
} = {}) {
  if (apiVersion !== 'beta')
    throw new Error(
      'This connector requires the explicit Graph beta sign-in event-type filter. Use Log Analytics for the stable production data path.',
    );
  if (!Number.isInteger(maxEvents) || maxEvents < 1 || maxEvents > 50000)
    throw new Error('maxEvents must be an integer between 1 and 50000.');
  if (typeof user !== 'string' || user.length > 254 || /[\u0000-\u001f]/.test(user))
    throw new Error('Supply a valid user principal name or user ID.');
  const range = validateTimeRange(start, end);
  const filter = [
    `createdDateTime ge ${range.start} and createdDateTime lt ${range.end}`,
    "signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser')",
  ];
  if (user.trim()) {
    const field = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      user.trim(),
    )
      ? 'userId'
      : 'userPrincipalName';
    filter.push(`${field} eq '${user.trim().replaceAll("'", "''")}'`);
  }
  let next = new URL('https://graph.microsoft.com/beta/auditLogs/signIns');
  next.searchParams.set('$filter', filter.map((part) => `(${part})`).join(' and '));
  next.searchParams.set('$top', String(Math.min(1000, maxEvents)));
  const events = [];
  const ids = new Set();
  const seenPages = new Set();
  let pages = 0;
  let truncated = false;
  const warnings = [
    'Graph beta is used explicitly to retrieve both interactive and non-interactive user sign-ins. Microsoft does not support beta APIs for production applications; prefer Log Analytics for a production investigation.',
    'Results reflect retained and ingested logs in the requested window. Absence of a sign-in is not proof that it did not occur.',
  ];
  while (next) {
    next = trustedUrl(next, 'graph.microsoft.com');
    if (!/^\/beta\/auditLogs\/signIns$/i.test(next.pathname))
      throw new ConnectorError('Refused a continuation outside the sign-in log endpoint.', {
        code: 'UnsafeContinuation',
      });
    if (seenPages.has(next.toString()))
      throw new ConnectorError(
        'Microsoft returned a repeated continuation page. Retry with a smaller window.',
        { code: 'InvalidContinuation' },
      );
    seenPages.add(next.toString());
    const response = await requestJson({
      url: next,
      credential,
      scope: SCOPES.graph,
      fetchImpl,
      sleepImpl,
    });
    pages++;
    if (!Array.isArray(response.value))
      throw new ConnectorError('Microsoft sign-in response did not contain an event array.', {
        code: 'InvalidResponse',
      });
    for (const item of response.value) {
      if (!item || typeof item !== 'object' || Array.isArray(item))
        throw new ConnectorError('Microsoft returned an invalid sign-in event.', {
          code: 'InvalidResponse',
        });
      const observationKey = JSON.stringify(item);
      if (ids.has(observationKey)) continue;
      if (events.length >= maxEvents) {
        truncated = true;
        break;
      }
      events.push(item);
      ids.add(observationKey);
    }
    next = response['@odata.nextLink'] || null;
    if (events.length >= maxEvents && next) truncated = true;
    if (pages >= 100 && next) truncated = true;
    if (truncated) break;
  }
  if (truncated)
    warnings.push(
      `Collection stopped at the configured event/page limit (${events.length} events, ${pages} pages). Narrow the time range; counts and spikes are based on an incomplete sample.`,
    );
  if (events.some((event) => !Object.hasOwn(event, 'appliedConditionalAccessPolicies')))
    warnings.push(
      'Some events omit appliedConditionalAccessPolicies. Verify CA read permissions and supported roles; policy attribution is incomplete.',
    );
  return {
    events,
    warnings,
    metadata: {
      source: 'graph',
      apiVersion,
      complete: !truncated,
      truncated,
      pages,
      count: events.length,
      requestedStart: range.start,
      requestedEnd: range.end,
      collectedAt: new Date().toISOString(),
      coverage: 'interactive and non-interactive user sign-ins',
      maxEvents,
    },
  };
}
