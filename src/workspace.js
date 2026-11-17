import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { normalizeEvents } from './core/normalize.js';
import { analyze } from './core/analyze.js';
import { buildKql } from './core/kql.js';
import { fetchGraphSignIns } from './connectors/graph.js';
import { runLogAnalyticsQuery } from './connectors/log-analytics.js';

export const demoFile = new URL('../fixtures/demo-signins.json', import.meta.url);
function validateTimestamp(value) {
  if (
    value &&
    (typeof value !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value) ||
      !Number.isFinite(Date.parse(value)))
  )
    throw new Error('Use ISO timestamps with an explicit timezone, such as 2026-11-16T09:00:00Z.');
}
export function timeRange(start, end, hours = 24) {
  validateTimestamp(start);
  validateTimestamp(end);
  const finish = end ? new Date(end) : new Date();
  const begin = start ? new Date(start) : new Date(finish.getTime() - Number(hours) * 3600000);
  if (!Number.isFinite(begin.getTime()) || !Number.isFinite(finish.getTime()) || begin >= finish)
    throw new Error('Provide a valid start time before the end time.');
  if (finish - begin > 31 * 86400000) throw new Error('Limit each collection to 31 days or fewer.');
  return { start: begin.toISOString(), end: finish.toISOString() };
}
export function filterEvents(events, { user = '', start, end, interaction = 'all' } = {}) {
  validateTimestamp(start);
  validateTimestamp(end);
  if (!['all', 'interactive', 'nonInteractive'].includes(interaction))
    throw new Error('Invalid interaction type.');
  if (start && !Number.isFinite(Date.parse(start))) throw new Error('Invalid start time.');
  if (end && !Number.isFinite(Date.parse(end))) throw new Error('Invalid end time.');
  if (start && end && Date.parse(start) >= Date.parse(end))
    throw new Error('Start must precede end.');
  const term = String(user).trim().toLowerCase();
  return events.filter(
    (e) =>
      (!term ||
        [e.userPrincipalName, e.userDisplayName, e.userId].some((v) =>
          String(v || '')
            .toLowerCase()
            .includes(term),
        )) &&
      (!start || Date.parse(e.timestamp) >= Date.parse(start)) &&
      (!end || Date.parse(e.timestamp) <= Date.parse(end)) &&
      (interaction === 'all' ||
        (interaction === 'interactive' ? e.isInteractive === true : e.isInteractive === false)),
  );
}
export async function loadDataset(data, source = 'offline', extra = {}) {
  const imported = data?.investigation?.events || data;
  const events = normalizeEvents(imported, { source });
  if (events.length > 50000)
    throw new Error(
      'The local workspace supports at most 50,000 records per dataset. Narrow the collection window.',
    );
  if (events.length && !events.some((e) => e.timestamp || e.userPrincipalName))
    throw new Error(
      'No recognizable sign-in records were found. Import Graph JSON or Log Analytics JSON results.',
    );
  return {
    events,
    metadata: {
      datasetId: randomUUID(),
      source,
      demo: source === 'demo',
      loadedAt: new Date().toISOString(),
      complete: source === 'demo',
      warnings:
        source === 'offline'
          ? ['Offline file coverage cannot be verified. Missing records may change conclusions.']
          : [],
      ...extra,
    },
  };
}
export async function loadDemo() {
  return loadDataset(JSON.parse(await readFile(demoFile, 'utf8')), 'demo');
}
export function investigate(dataset, filters = {}) {
  const events = filterEvents(dataset.events, filters);
  return {
    events,
    analysis: analyze(events),
    metadata: {
      ...dataset.metadata,
      scope: filters,
      datasetEvents: dataset.events.length,
      scopedEvents: events.length,
    },
  };
}
export async function collect({
  source,
  credential,
  workspaceId,
  user,
  start,
  end,
  hours,
  maxEvents = 5000,
}) {
  const range = timeRange(start, end, hours);
  let result;
  if (source === 'graph')
    result = await fetchGraphSignIns({ user, ...range, maxEvents, credential });
  else if (source === 'log-analytics') {
    const { query, warnings } = buildKql({
      preset: 'user',
      user,
      ...range,
      limit: maxEvents,
      mode: 'events',
    });
    result = await runLogAnalyticsQuery({
      workspaceId,
      query,
      timespan: `${range.start}/${range.end}`,
      credential,
    });
    result.warnings = [...warnings, ...(result.warnings || [])];
  } else throw new Error('Select graph or log-analytics for cloud collection.');
  return loadDataset(result.events, source, {
    ...result.metadata,
    warnings: result.warnings || [],
    range,
  });
}
