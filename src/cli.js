#!/usr/bin/env node
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { parseArgs } from 'node:util';
import { serve } from './server.js';
import { loadDemo, loadDataset, investigate, collect, timeRange } from './workspace.js';
import { buildKql } from './core/kql.js';
import { createCredential, getAuthStatus, SCOPES } from './connectors/auth.js';
import { runLogAnalyticsQuery } from './connectors/log-analytics.js';
import { evidenceBundle, markdownReport } from './report.js';

const help = `Traceglass 0.1 — Entra Conditional Access evidence workspace

  node src/cli.js serve [--port 4318]
  node src/cli.js investigate --demo [--user alex.morgan@example.com]
  node src/cli.js investigate --file data/signins.json --user person@example.com
  node src/cli.js collect --source graph --user person@example.com --hours 24 --out exports/case.json
  node src/cli.js collect --source log-analytics --workspace <GUID> --user person@example.com
  node src/cli.js query --preset risky --hours 24 [--run --workspace <GUID>]
  node src/cli.js query --preset ip --cidr 203.0.113.0/24 --mode distinct
  node src/cli.js query --spec data/query-spec.json [--run]
  node src/cli.js spikes --file data/signins.json
  node src/cli.js login [--source graph|log-analytics]
  node src/cli.js doctor

Options: --format text|json|markdown, --out <file>, --start/--end <ISO UTC>,
         --interaction all|interactive|nonInteractive, --limit 5000, --help
Use --file - to read JSON from stdin. All timestamps are UTC.
Set credential variables in .env and launch with node --env-file-if-exists=.env.
Cloud reads require authorized Graph / Log Analytics permissions; no tenant writes.
`;
const stringOptions = [
  'port',
  'file',
  'user',
  'start',
  'end',
  'hours',
  'source',
  'workspace',
  'out',
  'format',
  'interaction',
  'preset',
  'ip',
  'cidr',
  'mode',
  'limit',
  'spec',
];
const { values: args, positionals } = parseArgs({
  allowPositionals: true,
  options: Object.fromEntries([
    ...stringOptions.map((k) => [k, { type: 'string' }]),
    ...['demo', 'run', 'help'].map((k) => [k, { type: 'boolean' }]),
  ]),
});
async function readJson(file) {
  if (file === '-') {
    let text = '';
    for await (const chunk of process.stdin) {
      text += chunk;
      if (text.length > 20 * 1024 * 1024) throw new Error('Input exceeds 20 MB.');
    }
    return JSON.parse(text);
  }
  return JSON.parse(await readFile(file, 'utf8'));
}
async function emit(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  if (args.out) {
    await mkdir(dirname(args.out), { recursive: true });
    await writeFile(args.out, text + '\n', { mode: 0o600 });
    console.error(`Saved ${args.out}`);
  } else console.log(text);
}
async function credential() {
  return createCredential({ onDeviceCode: ({ message }) => console.error(message) });
}
function terminalReport(result) {
  const { summary } = result.analysis;
  const lines = [
    `TRACEGLASS  |  ${result.metadata.demo ? 'SYNTHETIC DEMO' : result.metadata.source.toUpperCase()}`,
    `${summary.total} records · ${summary.interactive} interactive · ${summary.nonInteractive} non-interactive`,
    `${summary.failures} sign-in failures · ${summary.caFailures} CA failures · ${summary.reportOnlyFailures} report-only failures`,
    '',
    'FINDINGS',
  ];
  for (const f of result.analysis.findings)
    lines.push(
      `[${f.severity.toUpperCase()}] ${f.title}`,
      `  ${f.detail}`,
      `  Evidence: ${(f.eventIds || []).join(', ')}`,
    );
  lines.push('', 'TIMELINE (UTC)');
  for (const e of result.events)
    lines.push(
      `${e.timestamp || 'Unknown time'}  ${e.isInteractive === true ? 'INTERACTIVE    ' : e.isInteractive === false ? 'NON-INTERACTIVE' : 'UNKNOWN        '}  ${String(e.status.errorCode ?? '?').padEnd(6)} CA:${e.conditionalAccessStatus}  ${e.appDisplayName} → ${e.resourceDisplayName}  [${e.id}]`,
    );
  lines.push('', 'LINK EVIDENCE');
  for (const l of result.analysis.links)
    lines.push(`${l.from} → ${l.to}  [${l.strength}] ${l.reason}`);
  lines.push('', 'COVERAGE');
  for (const warning of [...(result.metadata.warnings || []), ...(result.analysis.caveats || [])])
    lines.push(`- ${warning}`);
  return lines.join('\n');
}
async function outputInvestigation(result) {
  if (args.format && !['text', 'json', 'markdown'].includes(args.format))
    throw new Error('Format must be text, json, or markdown.');
  await emit(
    args.format === 'json'
      ? evidenceBundle(result)
      : args.format === 'markdown'
        ? markdownReport(result)
        : terminalReport(result),
  );
}
async function main() {
  const command = positionals[0];
  if (!command || args.help || command === 'help') return emit(help);
  if (command === 'serve')
    return serve({ port: Number(args.port || process.env.TRACEGLASS_PORT || 4318) });
  if (command === 'doctor')
    return emit({
      node: process.version,
      authentication: getAuthStatus(),
      workspaceConfigured: Boolean(process.env.TRACEGLASS_WORKSPACE_ID),
      liveConnectionTested: false,
      dataStorage: 'Memory only unless you explicitly export a file',
      listenAddress: '127.0.0.1',
    });
  if (command === 'login') {
    const source = args.source || 'graph';
    if (!['graph', 'log-analytics'].includes(source))
      throw new Error('Select graph or log-analytics for authentication.');
    const c = await credential();
    try {
      await c.getToken(source === 'log-analytics' ? SCOPES.logs : SCOPES.graph);
    } catch {
      throw new Error(
        'Authentication failed. Verify the configured credential, tenant, consent, and tenant authentication policy. SDK details are withheld to protect credentials.',
      );
    }
    return emit(
      `${source === 'log-analytics' ? 'Log Analytics' : 'Graph'} token acquired for this process. No token was written to disk. Each CLI command acquires its own credential; Azure CLI manages its own existing session.`,
    );
  }
  if (command === 'query') {
    const spec = args.spec
      ? await readJson(args.spec)
      : {
          preset: args.preset || 'user',
          user: args.user,
          ip: args.ip,
          cidr: args.cidr,
          hours: Number(args.hours || 24),
          limit: Number(args.limit || 5000),
          mode: args.mode || 'events',
          ...(args.start || args.end ? { start: args.start, end: args.end } : {}),
        };
    const built = buildKql(spec);
    if (!args.run) return emit(built.query);
    const range = timeRange(spec.start, spec.end, spec.hours || 24);
    const result = await runLogAnalyticsQuery({
      workspaceId: args.workspace || process.env.TRACEGLASS_WORKSPACE_ID,
      query: built.query,
      timespan: `${range.start}/${range.end}`,
      credential: await credential(),
    });
    return emit({ ...result, warnings: [...built.warnings, ...result.warnings] });
  }
  if (command === 'collect') {
    const dataset = await collect({
      source: args.source || 'graph',
      user: args.user,
      start: args.start,
      end: args.end,
      hours: Number(args.hours || 24),
      maxEvents: Number(args.limit || 5000),
      workspaceId: args.workspace || process.env.TRACEGLASS_WORKSPACE_ID,
      credential: await credential(),
    });
    const result = investigate(dataset);
    if (!args.format) args.format = 'json';
    return outputInvestigation(result);
  }
  if (command === 'investigate' || command === 'spikes') {
    if (!args.file && !args.demo) throw new Error('Choose --file <JSON export> or --demo.');
    const dataset = args.file ? await loadDataset(await readJson(args.file)) : await loadDemo();
    const result = investigate(dataset, {
      user: args.user,
      start: args.start,
      end: args.end,
      interaction: args.interaction || 'all',
    });
    return command === 'spikes'
      ? emit({
          spikes: result.analysis.spikes,
          policies: result.analysis.policies,
          metadata: result.metadata,
        })
      : outputInvestigation(result);
  }
  throw new Error(`Unknown command: ${command}. Run with --help.`);
}
main().catch((error) => {
  console.error(`Traceglass: ${error.message}`);
  process.exitCode = 1;
});
