import { SCOPES } from './auth.js';
import { ConnectorError, requestJson } from './http.js';

function validateTimespan(timespan) {
  if (timespan === undefined) return 'P1D';
  if (typeof timespan !== 'string')
    throw new Error(
      'Log Analytics timespan must be a bounded ISO 8601 duration or timestamp interval.',
    );
  const duration = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$/.exec(timespan);
  if (duration) {
    const minutes =
      Number(duration[1] || 0) * 1440 + Number(duration[2] || 0) * 60 + Number(duration[3] || 0);
    if (minutes > 0 && minutes <= 44640) return timespan;
  }
  const interval = timespan.split('/');
  if (
    interval.length === 2 &&
    interval.every((item) => /^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(item))
  ) {
    const delta = Date.parse(interval[1]) - Date.parse(interval[0]);
    if (Number.isFinite(delta) && delta > 0 && delta <= 31 * 86400000) return timespan;
  }
  throw new Error('Log Analytics timespan must be greater than zero and no more than 31 days.');
}

export async function runLogAnalyticsQuery({
  workspaceId,
  query,
  timespan = 'P1D',
  credential,
  fetchImpl,
  sleepImpl,
  maxRows = 50000,
} = {}) {
  if (
    typeof workspaceId !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(workspaceId)
  )
    throw new Error(
      'Provide the Log Analytics workspace ID (a UUID), not its name or Azure resource ID.',
    );
  if (typeof query !== 'string' || !query.trim() || query.length > 100000)
    throw new Error('A non-empty generated KQL query of at most 100000 characters is required.');
  if (/^\s*\./.test(query)) throw new Error('Kusto management commands are not allowed.');
  if (!Number.isInteger(maxRows) || maxRows < 1 || maxRows > 50000)
    throw new Error('maxRows must be between 1 and 50000.');
  const boundedTimespan = validateTimespan(timespan);
  const response = await requestJson({
    url: new URL(`https://api.loganalytics.azure.com/v1/workspaces/${workspaceId}/query`),
    credential,
    scope: SCOPES.logs,
    method: 'POST',
    body: { query, timespan: boundedTimespan },
    headers: { Prefer: 'wait=30', 'x-ms-app': 'Traceglass' },
    timeoutMs: 45000,
    fetchImpl,
    sleepImpl,
  });
  if (!Array.isArray(response.tables))
    throw new ConnectorError('Log Analytics did not return result tables.', {
      code: 'InvalidResponse',
    });
  const primary =
    response.tables.find((table) => table.name === 'PrimaryResult') || response.tables[0];
  if (
    primary &&
    (!Array.isArray(primary.columns) ||
      !Array.isArray(primary.rows) ||
      primary.columns.some((column) => typeof column?.name !== 'string'))
  )
    throw new ConnectorError('Log Analytics returned an invalid table shape.', {
      code: 'InvalidResponse',
    });
  const rows = primary?.rows || [];
  const events = rows.slice(0, maxRows).map((row) => {
    if (!Array.isArray(row) || row.length !== primary.columns.length)
      throw new ConnectorError('Log Analytics returned a row with an invalid column count.', {
        code: 'InvalidResponse',
      });
    return Object.fromEntries(primary.columns.map((column, index) => [column.name, row[index]]));
  });
  const partial = Boolean(response.error);
  const queryLimit = /\|\s*(?:take|limit)\s+(\d+)\s*;?\s*$/i.exec(query);
  const limitReached = Boolean(queryLimit && rows.length >= Number(queryLimit[1]));
  const truncated = rows.length > maxRows || limitReached;
  const warnings = [
    'Workspace results depend on diagnostic export, retention, ingestion delay, table permissions, and the generated query limit.',
  ];
  if (partial)
    warnings.push(
      'Log Analytics returned PartialError or another response error with results. This is an incomplete result; narrow the query and verify table access before drawing conclusions.',
    );
  if (rows.length > maxRows)
    warnings.push(`Client result limit reached (${maxRows} rows). This is an incomplete result.`);
  if (limitReached)
    warnings.push(
      `Generated query row limit reached (${queryLimit[1]} rows). More matching records may exist; narrow the time window before interpreting counts or spikes.`,
    );
  // Preserve useful typed results while bounding client memory passed to the rest of the app.
  const tables = primary ? [{ ...primary, rows: rows.slice(0, maxRows) }] : [];
  return {
    tables,
    events,
    warnings,
    metadata: {
      source: 'log-analytics',
      complete: !partial && !truncated,
      partial,
      truncated,
      limitReached,
      count: events.length,
      timespan: boundedTimespan,
      collectedAt: new Date().toISOString(),
      workspaceId,
    },
  };
}
