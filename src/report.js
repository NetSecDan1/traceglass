import { createHash } from 'node:crypto';
const cell = (value) =>
  String(value ?? '')
    .replace(/[\r\n|]/g, ' ')
    .replace(/([\\`*_<>])/g, '\\$1');
export function evidenceBundle(investigation) {
  const payload = JSON.stringify(investigation);
  return {
    schemaVersion: '1.0',
    application: 'Traceglass',
    exportedAt: new Date().toISOString(),
    integrity: {
      algorithm: 'SHA-256',
      digest: createHash('sha256').update(payload).digest('hex'),
      scope:
        'UTF-8 JSON.stringify(investigation). Detects changes to this export; does not authenticate the source.',
    },
    investigation,
  };
}
export function markdownReport(investigation) {
  const { events, analysis, metadata } = investigation;
  const report = evidenceBundle(investigation);
  const lines = [
    '# Traceglass investigation',
    '',
    `Exported: ${report.exportedAt}`,
    `Source: ${cell(metadata.source)}${metadata.demo ? ' — SYNTHETIC DEMO' : ''}`,
    `Events in scope: ${events.length}`,
    '',
    '> Conclusions describe recorded outcomes. Historical policy intent, complete collection, and causality require independent verification.',
    '',
    '## Findings',
    '',
  ];
  for (const f of analysis.findings)
    lines.push(
      `### ${cell(f.title)}`,
      '',
      cell(f.detail),
      '',
      `Evidence event IDs: ${(f.eventIds || []).map(cell).join(', ')}`,
      '',
    );
  lines.push('## Coverage and caveats', '');
  for (const c of [...(metadata.warnings || []), ...(analysis.caveats || [])])
    lines.push(`- ${cell(c)}`);
  lines.push(
    '',
    '## Event timeline (UTC)',
    '',
    '| Time | User | Flow | Application / resource | Sign-in result | CA result | Event ID |',
    '|---|---|---|---|---|---|---|',
  );
  for (const e of events)
    lines.push(
      `| ${cell(e.timestamp)} | ${cell(e.userPrincipalName)} | ${e.isInteractive === true ? 'Interactive' : e.isInteractive === false ? 'Non-interactive' : 'Unknown'} | ${cell(e.appDisplayName)} / ${cell(e.resourceDisplayName)} | ${cell(e.status.errorCode ?? 'Unknown')} | ${cell(e.conditionalAccessStatus)} | ${cell(e.id)} |`,
    );
  lines.push(
    '',
    '## Integrity',
    '',
    `Investigation JSON SHA-256: \`${report.integrity.digest}\``,
    '',
    report.integrity.scope,
    '',
    'The companion JSON export contains the complete normalized evidence and original records. This report contains identity data; share only through approved incident channels.',
    '',
  );
  return lines.join('\n');
}
