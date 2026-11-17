const icons = {
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4.5 4.5"/>',
  investigate: '<circle cx="11" cy="11" r="7"/><path d="m16 16 5 5M8 11h6M11 8v6"/>',
  hunt: '<path d="M8 4H4v4M16 4h4v4M20 16v4h-4M8 20H4v-4"/><circle cx="12" cy="12" r="4"/><path d="M12 10v4M10 12h4"/>',
  signals: '<path d="M3 18V6M3 18h18M6 14l4-5 4 3 6-7"/><path d="M17 5h3v3"/>',
  connections: '<path d="M9 5H7a4 4 0 0 0 0 8h3M15 19h2a4 4 0 0 0 0-8h-3M8 12h8"/>',
  flask: '<path d="M9 3h6M10 3v7l-5 8a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-8V3M8 15h8"/>',
  upload: '<path d="M12 16V3m-4 4 4-4 4 4M4 15v5h16v-5"/>',
  download: '<path d="M12 3v13m-4-4 4 4 4-4M4 17v4h16v-4"/>',
  chevron: '<path d="m8 10 4 4 4-4"/>',
  arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
  clock: '<circle cx="12" cy="12" r="8"/><path d="M12 7v5l3 2"/>',
  user: '<circle cx="12" cy="8" r="3"/><path d="M5 21v-3a7 7 0 0 1 14 0v3"/>',
  refresh:
    '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 7a7 7 0 0 1 12 0l2 5M4 12l2 5a7 7 0 0 0 12 0"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  alert: '<path d="m12 3 10 17H2L12 3Z"/><path d="M12 9v5m0 3v.2"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.2"/>',
  keyboard:
    '<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M6 9h.1M10 9h.1M14 9h.1M18 9h.1M6 12h.1M10 12h.1M14 12h.1M18 12h.1M7 16h10"/>',
  copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  code: '<path d="m7 6-6 6 6 6m10-12 6 6-6 6M14 3l-4 18"/>',
  play: '<path d="m8 4 12 8-12 8V4Z"/>',
  network:
    '<circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><path d="M12 8v5M5 16v-3h14v3"/>',
  layers: '<path d="m12 3 10 5-10 5L2 8l10-5ZM2 12l10 5 10-5M2 16l10 5 10-5"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V6a4 4 0 0 1 8 0v4M12 14v3"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z"/>',
  terminal: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m6 9 3 3-3 3m6 0h5"/>',
  close: '<path d="m6 6 12 12M18 6 6 18"/>',
  left: '<path d="m14 6-6 6 6 6"/>',
  right: '<path d="m10 6 6 6-6 6"/>',
  filter: '<path d="M3 5h18l-7 8v6l-4 2v-8L3 5Z"/>',
};
const icon = (name) =>
  `<svg viewBox="0 0 24 24" aria-hidden="true">${icons[name] || icons.info}</svg>`;
const esc = (value) =>
  String(value ?? '').replace(
    /[&<>"']/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char],
  );
const fmt = (value, options = {}) => {
  if (!value) return 'Unknown time';
  const date = new Date(value);
  return Number.isNaN(+date)
    ? 'Unknown time'
    : date.toLocaleString('en-GB', { timeZone: 'UTC', ...options });
};
const time = (value) =>
  fmt(value, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const date = (value) => fmt(value, { day: '2-digit', month: 'short', year: 'numeric' });
const num = (value) => Number(value || 0).toLocaleString('en-US');
const pct = (value) => (value == null ? 'n/a' : `${(Number(value) * 100).toFixed(1)}%`);
const eventOutcome = (event) =>
  event.status?.errorCode === 0
    ? 'success'
    : event.status?.errorCode == null
      ? 'unknown'
      : 'failure';
const caFailed = (event) =>
  event.conditionalAccessStatus === 'failure' ||
  event.policies?.some((policy) => policy.result === 'failure');
const interactionLabel = (event) =>
  event.isInteractive === true
    ? 'Interactive'
    : event.isInteractive === false
      ? 'Non-interactive'
      : 'Unknown';
const isoField = (value) =>
  value ? new Date(value.endsWith('Z') ? value : `${value}Z`).toISOString() : '';
const sourceNames = {
  demo: 'Synthetic demo',
  offline: 'Offline evidence',
  graph: 'Microsoft Graph',
  'log-analytics': 'Log Analytics',
};
const fields = [
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
];
const fieldLabels = {
  UserPrincipalName: 'User principal name',
  UserId: 'User ID',
  IPAddress: 'IP address / range',
  AppDisplayName: 'Application',
  AppId: 'Application ID',
  ResourceDisplayName: 'Resource',
  ConditionalAccessStatus: 'Conditional Access',
  ResultType: 'Result code',
  RiskLevelDuringSignIn: 'Sign-in risk',
  RiskState: 'Risk state',
  IsInteractive: 'Interactive',
  CorrelationId: 'Correlation ID',
  ClientAppUsed: 'Client application',
};
const operators = {
  eq: 'equals',
  neq: 'does not equal',
  contains: 'contains',
  startsWith: 'starts with',
  in: 'is one of',
  cidr: 'is in CIDR',
};
const templates = [
  {
    id: 'user',
    icon: 'user',
    title: 'User investigation',
    description: 'Follow an identity across sign-ins',
  },
  {
    id: 'risky',
    icon: 'shield',
    title: 'Risky sign-ins',
    description: 'Elevated identity risk signals',
  },
  {
    id: 'ip',
    icon: 'globe',
    title: 'IP & network hunt',
    description: 'Find an address or CIDR range',
  },
  {
    id: 'caFailures',
    icon: 'lock',
    title: 'CA enforcement',
    description: 'Inspect blocked access attempts',
  },
  {
    id: 'spikes',
    icon: 'signals',
    title: 'Failure spikes',
    description: 'Compare rates across time bins',
  },
  {
    id: 'patterns',
    icon: 'layers',
    title: 'Recurring patterns',
    description: 'Group repeat sign-in behavior',
  },
];
const state = {
  view: 'investigate',
  csrfToken: '',
  config: {},
  data: null,
  selected: null,
  detailTab: 'evidence',
  source: 'demo',
  user: 'alex.morgan@example.com',
  start: '',
  end: '',
  interaction: 'all',
  page: 0,
  pageSize: 12,
  spec: {
    preset: 'user',
    user: 'alex.morgan@example.com',
    ip: '',
    cidr: '',
    hours: 24,
    limit: 500,
    mode: 'events',
    filters: [],
  },
  query: '',
  queryWarnings: [],
  queryResult: null,
  queryError: '',
  drag: null,
  auth: null,
  building: 0,
};
const main = document.querySelector('#main');
let toastTimer, buildTimer, authPoll;

function toast(message, error = false) {
  const el = document.querySelector('#toast');
  el.textContent = message;
  el.classList.toggle('error', error);
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(
    () => {
      el.hidden = true;
    },
    error ? 11000 : 4500,
  );
}
async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers:
      body === undefined
        ? {}
        : { 'Content-Type': 'application/json', 'X-Traceglass-CSRF': state.csrfToken },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let result;
  try {
    result = JSON.parse(text);
  } catch {
    throw new Error(
      response.ok
        ? 'The server returned an unexpected response.'
        : `Request failed (${response.status}).`,
    );
  }
  if (!response.ok)
    throw new Error(
      typeof result.error === 'string'
        ? result.error
        : result.error?.message || result.message || `Request failed (${response.status}).`,
    );
  return result;
}
function investigationParams() {
  const params = new URLSearchParams();
  if (state.user.trim()) params.set('user', state.user.trim());
  if (state.start) params.set('start', isoField(state.start));
  if (state.end) params.set('end', isoField(state.end));
  if (state.interaction !== 'all') params.set('interaction', state.interaction);
  return params;
}
function setData(data) {
  state.data = data;
  state.source = data.metadata?.source || state.source;
  state.page = 0;
  if (!data.events?.find((event) => event.id === state.selected))
    state.selected =
      (
        data.events?.find((event) => event.isInteractive === false && caFailed(event)) ||
        data.events?.find(caFailed) ||
        data.events?.[0]
      )?.id || null;
  updateChrome();
}
function updateChrome() {
  const badge = document.querySelector('#source-badge');
  badge.innerHTML = `<span></span>${esc(sourceNames[state.source] || state.source)}`;
  badge.classList.toggle('live', ['graph', 'log-analytics'].includes(state.source));
  const labels = {
    investigate: 'Investigate',
    hunt: 'Hunt builder',
    signals: 'Signals',
    connections: 'Connections',
  };
  document.querySelector('#page-breadcrumb').textContent = labels[state.view];
  document.querySelectorAll('[data-view]').forEach((el) => {
    el.classList.toggle('active', el.dataset.view === state.view);
    el.setAttribute('aria-current', el.dataset.view === state.view ? 'page' : 'false');
  });
  const metadata = state.data?.metadata || {};
  document.querySelector('#footer-status').textContent =
    state.source === 'demo'
      ? 'Synthetic data · no tenant connected'
      : `${sourceNames[state.source] || state.source} · ${metadata.truncated ? 'Partial collection' : metadata.complete === false ? 'Coverage incomplete' : 'Read-only analysis'}`;
}
async function loadInvestigation() {
  main.classList.add('loading-overlay');
  try {
    setData(await api(`/api/investigation?${investigationParams()}`));
    render();
  } catch (error) {
    toast(error.message, true);
  } finally {
    main.classList.remove('loading-overlay');
  }
}
function heading(title, description, eyebrow = 'CONDITIONAL ACCESS · INVESTIGATION', actions = '') {
  return `<div class="page-heading"><div><div class="eyebrow">${esc(eyebrow)}</div><h1>${esc(title)}</h1><p>${esc(description)}</p></div><div class="heading-actions">${actions}</div></div>`;
}
function exportActions() {
  return `<button class="button" data-action="import">${icon('upload')}Import</button><div class="export-menu"><button class="button" data-action="toggle-export" aria-expanded="false">${icon('download')}Export case${icon('chevron')}</button><div class="dropdown-menu" hidden><a href="/api/export?${investigationParams()}&format=markdown" download>Investigation report (.md)</a><a href="/api/export?${investigationParams()}&format=json" download>Evidence bundle (.json)</a></div></div>`;
}
function searchbar() {
  return `<form class="searchbar" id="investigation-search"><div class="search-user">${icon('search')}<label class="screen-reader" for="user-search">User principal name</label><input id="user-search" name="user" type="search" autocomplete="off" placeholder="Search a user principal name…" value="${esc(state.user)}"></div><span class="search-divider"></span><label class="time-field">From UTC<input name="start" type="datetime-local" value="${esc(state.start)}" aria-label="Start date and time UTC"></label><label class="time-field">To UTC<input name="end" type="datetime-local" value="${esc(state.end)}" aria-label="End date and time UTC"></label><button class="button primary" type="submit">Investigate${icon('arrow')}</button></form>`;
}
function metrics() {
  const s = state.data?.analysis?.summary || {};
  return `<section class="metrics" aria-label="Investigation summary">${[
    ['All sign-ins', s.total, 'clock', 'Across selected evidence', ''],
    ['Interactive', s.interactive, 'user', 'User-present authentication', ''],
    ['Non-interactive', s.nonInteractive, 'refresh', 'Background authentication', ''],
    ['CA failures', s.caFailures, 'shield', 'Enforced policy outcomes', 'danger'],
    [
      'Other failures',
      Math.max(0, (s.failures || 0) - (s.caFailures || 0)),
      'alert',
      'Review separate causes',
      'amber',
    ],
  ]
    .map(
      ([label, value, i, note, color]) =>
        `<div class="metric"><div class="metric-label">${icon(i)}${label}</div><div class="metric-value ${color}">${num(value)}</div><div class="metric-note">${note}</div></div>`,
    )
    .join('')}</section>`;
}
function warningsMarkup() {
  const meta = state.data?.metadata || {};
  const warnings = [...(meta.warnings || [])];
  if (meta.truncated)
    warnings.unshift(
      'The collection reached its row limit. Findings describe only the collected evidence. Narrow the time range for a complete investigation.',
    );
  if (meta.complete === false && !meta.truncated)
    warnings.unshift(
      'Collection coverage is incomplete. Review the source warnings before drawing a conclusion.',
    );
  return warnings.length
    ? `<div class="warning-strip"><ul>${[...new Set(warnings)].map((w) => `<li>${esc(typeof w === 'string' ? w : w.message || JSON.stringify(w))}</li>`).join('')}</ul></div>`
    : '';
}
function evidenceBanner() {
  const findings = state.data?.analysis?.findings || [];
  const finding =
    findings.find((f) => f.severity === 'critical') ||
    findings.find((f) => f.severity === 'warning') ||
    findings[0];
  return `<div class="evidence-banner"><span class="banner-icon">${icon('info')}</span><div><h3>${esc(finding?.title || 'A sign-in result is one part of the story.')}</h3><p>${esc(finding?.detail || 'Compare enforced policy results and request context. Temporal proximity alone does not prove two events share a session or a cause.')}</p></div><button data-action="view-signals">View findings →</button></div>`;
}
function timeline() {
  const all = [...(state.data?.events || [])].sort(
    (a, b) => new Date(a.timestamp) - new Date(b.timestamp),
  );
  const events = all.slice(-45);
  const width = Math.max(740, events.length * 32 + 165);
  const x = (index) => 140 + index * ((width - 175) / Math.max(events.length - 1, 1));
  const y = (event) =>
    event.isInteractive === true ? 67 : event.isInteractive === false ? 155 : 205;
  const positions = new Map(events.map((event, index) => [event.id, { x: x(index), y: y(event) }]));
  const links = (state.data?.analysis?.links || [])
    .filter((link) => positions.has(link.from) && positions.has(link.to))
    .slice(0, 55)
    .map((link) => {
      const a = positions.get(link.from),
        b = positions.get(link.to),
        controlY = a.y === b.y ? a.y - 26 : (a.y + b.y) / 2;
      return `<path d="M${a.x},${a.y} C${a.x},${controlY} ${b.x},${controlY} ${b.x},${b.y}" fill="none" stroke="${link.strength === 'strong' ? '#8bac91' : '#bdcbb4'}" stroke-width="1" ${link.strength === 'strong' ? '' : 'stroke-dasharray="4 4"'} opacity=".8"><title>${esc(link.reason)} · ${esc(link.strength === 'strong' ? 'Shared identifier' : 'Contextual relationship, not a proven session')}</title></path>`;
    })
    .join('');
  const nodes = events
    .map((event, index) => {
      const p = positions.get(event.id),
        outcome = eventOutcome(event),
        color = outcome === 'success' ? '#699b79' : outcome === 'failure' ? '#c37762' : '#aab598',
        selected = event.id === state.selected;
      return `<g class="event-node" role="button" tabindex="0" data-event="${esc(event.id)}" aria-label="${esc(`${time(event.timestamp)} ${interactionLabel(event)} ${event.appDisplayName} ${outcome}`)}"><title>${esc(`${time(event.timestamp)} · ${event.appDisplayName} · ${outcome}`)}</title><circle class="outer" cx="${p.x}" cy="${p.y}" r="${selected ? 12 : 8}" fill="${selected ? '#f0f5e9' : 'white'}" stroke="${selected ? '#719e79' : '#d8e3cb'}" stroke-width="${selected ? 2 : 1}"/><circle cx="${p.x}" cy="${p.y}" r="${selected ? 5 : 4}" fill="${color}"/>${outcome === 'failure' ? `<path d="m${p.x - 2},${p.y - 2} 4,4m0,-4 -4,4" stroke="white" stroke-width="1"/>` : ''}${events.length < 18 || index % 3 === 0 || selected ? `<text x="${p.x}" y="${p.y + 24}" text-anchor="middle" style="font-size:10px">${time(event.timestamp).slice(0, 5)}</text>` : ''}</g>`;
    })
    .join('');
  return `<section class="panel timeline-panel"><div class="panel-heading"><div><h2>Authentication timeline</h2><p>Recorded requests, linked by available evidence</p></div><div class="segmented" aria-label="Sign-in type">${[
    ['all', 'All'],
    ['interactive', 'Interactive'],
    ['nonInteractive', 'Non-interactive'],
  ]
    .map(
      ([value, label]) =>
        `<button data-interaction="${value}" class="${state.interaction === value ? 'active' : ''}" aria-pressed="${state.interaction === value}">${label}</button>`,
    )
    .join(
      '',
    )}</div></div><div class="timeline-legend"><span class="legend-item"><span class="dot"></span>Sign-in succeeded</span><span class="legend-item"><span class="dot red"></span>Sign-in failed</span><span class="legend-item"><span class="legend-line"></span>Context, not proven causation</span></div>${events.length ? `<div class="timeline-scroller"><svg class="timeline-svg" style="width:${width}px" viewBox="0 0 ${width} 235" role="group" aria-label="Sign-in sequence by interaction type"><path d="M130 67H${width - 15}M130 155H${width - 15}" stroke="#e5ebdb" stroke-dasharray="3 4"/><text class="lane-label" x="12" y="65">Interactive</text><text x="12" y="80">User present</text><text class="lane-label" x="12" y="153">Non-interactive</text><text x="12" y="168">Background request</text>${events.some((e) => e.isInteractive == null) ? '<text class="lane-label" x="12" y="208">Unspecified</text>' : ''}${links}${nodes}</svg></div>` : emptyState('No events in this view', 'Adjust the user or time range, or import sign-in evidence.')}<div class="timeline-foot"><span>${events.length ? `${esc(date(events[0].timestamp))}${date(events[0].timestamp) !== date(events.at(-1).timestamp) ? ` – ${esc(date(events.at(-1).timestamp))}` : ''}` : 'No time range'} · UTC</span><span>Event sequence · ${all.length > 45 ? 'latest 45 events' : 'select a node for evidence'}</span></div></section>`;
}
function emptyState(title, detail) {
  return `<div class="empty-state">${icon('search')}<h3>${esc(title)}</h3><p>${esc(detail)}</p></div>`;
}
function outcomePill(event) {
  const outcome = eventOutcome(event);
  return `<span class="pill ${outcome === 'failure' ? 'fail' : outcome === 'unknown' ? 'neutral' : ''}">${outcome === 'success' ? 'Success' : outcome === 'failure' ? `Failed · ${esc(event.status.errorCode)}` : 'Unknown'}</span>`;
}
function caPill(event) {
  const value = event.conditionalAccessStatus;
  if (value === 'failure') return '<span class="pill fail">Failure</span>';
  if (value === 'success') return '<span class="pill">Satisfied</span>';
  if (value === 'notApplied') return '<span class="pill neutral">Not applied</span>';
  return '<span class="pill neutral">Unknown</span>';
}
function eventTable(events = state.data?.events || [], options = { paginate: true }) {
  if (!events.length)
    return emptyState('No matching sign-ins', 'Try a broader time window or a different identity.');
  const sorted = [...events].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  const maxPage = Math.max(0, Math.ceil(events.length / state.pageSize) - 1);
  if (state.page > maxPage) state.page = maxPage;
  const visible = options.paginate
    ? sorted.slice(state.page * state.pageSize, (state.page + 1) * state.pageSize)
    : sorted.slice(0, 100);
  return `<div class="table-scroll"><table><thead><tr><th>Time · UTC</th><th>Application / resource</th><th>Type</th><th>Sign-in</th><th>Conditional Access</th></tr></thead><tbody>${visible.map((event) => `<tr class="event-row ${event.id === state.selected ? 'selected' : ''}" data-event="${esc(event.id)}" tabindex="0" aria-label="${esc(`Inspect ${event.appDisplayName} at ${time(event.timestamp)}`)}"><td><span class="event-time">${esc(time(event.timestamp))}</span><span class="cell-sub">${esc(date(event.timestamp).slice(0, 6))}</span></td><td><span class="cell-main">${esc(event.appDisplayName || 'Unknown application')}</span><span class="cell-sub">${esc(event.resourceDisplayName || event.userPrincipalName || 'Unknown resource')}</span></td><td><span class="type-label">${icon(event.isInteractive ? 'user' : 'refresh')}${esc(interactionLabel(event))}</span></td><td>${outcomePill(event)}</td><td>${caPill(event)}</td></tr>`).join('')}</tbody></table></div>${options.paginate ? `<div class="pagination"><span>${state.page * state.pageSize + 1}–${Math.min((state.page + 1) * state.pageSize, events.length)} of ${num(events.length)} events</span><div class="pagination-buttons"><button class="icon-button" data-action="previous-page" aria-label="Previous events" ${state.page === 0 ? 'disabled' : ''}>${icon('left')}</button><button class="icon-button" data-action="next-page" aria-label="Next events" ${state.page >= maxPage ? 'disabled' : ''}>${icon('right')}</button></div></div>` : events.length > 100 ? '<div class="pagination">Showing the first 100 rows.</div>' : ''}`;
}
function keyValues(rows) {
  return `<dl class="detail-kv">${rows.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value == null || value === '' ? 'Not recorded' : value)}</dd>`).join('')}</dl>`;
}
function policyPill(result) {
  return `<span class="pill ${result === 'failure' ? 'fail' : result?.startsWith('reportOnly') ? 'warn' : result === 'success' ? '' : 'neutral'}">${esc({ success: 'Satisfied', failure: 'Failed', notApplied: 'Not applied', notEnabled: 'Disabled', reportOnlyFailure: 'Report-only failure', reportOnlySuccess: 'Report-only pass', reportOnlyNotApplied: 'Report-only skipped', reportOnlyInterrupted: 'Report-only interrupted' }[result] || result || 'Unknown')}</span>`;
}
function detailPanel() {
  const event = state.data?.events?.find((e) => e.id === state.selected);
  if (!event)
    return `<aside class="panel detail-panel"><div class="detail-empty">Select a sign-in to inspect its evidence.</div></aside>`;
  const links = (state.data.analysis?.links || []).filter(
    (l) => l.from === event.id || l.to === event.id,
  );
  const body =
    state.detailTab === 'raw'
      ? `<pre class="raw-json">${esc(JSON.stringify(event.observations || event.raw || event, null, 2))}</pre>`
      : `
  <section class="detail-section"><div class="section-label">Request context</div>${keyValues([
    ['User', event.userPrincipalName],
    ['Timestamp', `${date(event.timestamp)} ${time(event.timestamp)} UTC`],
    ['Type', interactionLabel(event)],
    ['Resource', event.resourceDisplayName],
    ['IP address', event.ipAddress],
    [
      'Location',
      [event.location?.city, event.location?.countryOrRegion].filter(Boolean).join(', '),
    ],
    ['Risk', event.riskLevel],
  ])}</section>
  <section class="detail-section"><div class="section-label">Conditional Access evidence</div>${keyValues(
    [
      ['Overall result', event.conditionalAccessStatus || 'Unknown'],
      [
        'Policy details',
        event.policyVisibility === 'missing' ? 'Not available' : 'Present in event',
      ],
    ],
  )}${event.policyVisibility === 'missing' ? '<div class="context-note">Policy details are missing. This can reflect permissions or source coverage; it is not evidence that no policies applied.</div>' : event.policies?.length ? event.policies.map((policy) => `<div class="policy-card ${policy.result === 'failure' ? 'failing' : ''}"><div class="policy-name"><span>${esc(policy.displayName || policy.id || 'Unnamed policy')}</span></div><div style="margin-top:6px">${policyPill(policy.result)}</div>${policy.enforcedGrantControls?.length ? `<div class="policy-detail">Grant controls · ${esc(policy.enforcedGrantControls.join(', '))}</div>` : ''}${policy.enforcedSessionControls?.length ? `<div class="policy-detail">Session controls · ${esc(policy.enforcedSessionControls.join(', '))}</div>` : ''}${policy.result?.startsWith('reportOnly') ? '<div class="policy-detail">Report-only result did not enforce a block.</div>' : ''}</div>`).join('') : '<div class="context-note">The event contains no applied policy entries. Check the overall CA status and source completeness.</div>'}</section>
  <section class="detail-section"><div class="section-label">Authentication result</div>${keyValues(
    [
      ['Result code', event.status?.errorCode],
      ['Reason', event.status?.failureReason],
      ['Details', event.status?.additionalDetails],
    ],
  )}${event.authenticationDetails?.length ? `<div class="context-note">${event.authenticationDetails.map((step) => `${esc(step.authenticationMethod || step.authenticationStepRequirement || 'Authentication step')}: ${esc(step.authenticationStepResultDetail || String(step.succeeded ?? 'Not recorded'))}`).join('<br>')}</div>` : ''}</section>
  <section class="detail-section"><div class="section-label">Device & correlation</div>${keyValues([
    ['Device', event.device?.displayName],
    ['OS', event.device?.operatingSystem],
    [
      'Compliant',
      event.device?.isCompliant === true
        ? 'Yes'
        : event.device?.isCompliant === false
          ? 'No'
          : 'Not recorded',
    ],
    [
      'Managed',
      event.device?.isManaged === true
        ? 'Yes'
        : event.device?.isManaged === false
          ? 'No'
          : 'Not recorded',
    ],
    ['Correlation ID', event.correlationId],
    ['Original request', event.originalRequestId],
    ['Session ID', event.sessionId],
  ])}</section>
  ${
    links.length
      ? `<section class="detail-section"><div class="section-label">Related evidence</div>${links
          .slice(0, 6)
          .map(
            (link) =>
              `<div class="context-note">${esc(link.reason)}<br><strong>${link.strength === 'strong' ? 'Shared identifier' : 'Context only · not a proven session'}</strong><br><button class="text-link" data-event="${esc(link.from === event.id ? link.to : link.from)}">Inspect related request →</button></div>`,
          )
          .join('')}</section>`
      : ''
  }
  <div class="context-note">This view explains the recorded outcome. Confirm policy intent and the configuration at the incident time before declaring “working as designed.”</div>`;
  return `<aside class="panel detail-panel" aria-label="Selected event evidence"><div class="detail-heading"><div class="detail-topline"><span class="eyebrow">SELECTED SIGN-IN</span>${outcomePill(event)}</div><h2>${esc(event.appDisplayName || 'Unknown application')}</h2><p>${esc(time(event.timestamp))} UTC <span aria-hidden="true">·</span> ${esc(interactionLabel(event))}</p></div><div class="detail-tabs" role="tablist" aria-label="Event detail"><button role="tab" aria-selected="${state.detailTab === 'evidence'}" data-detail-tab="evidence" class="${state.detailTab === 'evidence' ? 'active' : ''}">Evidence</button><button role="tab" aria-selected="${state.detailTab === 'raw'}" data-detail-tab="raw" class="${state.detailTab === 'raw' ? 'active' : ''}">Raw event</button></div><div class="detail-body">${body}</div></aside>`;
}
function renderInvestigation() {
  main.innerHTML =
    heading(
      'Sign-in investigation',
      'Understand what happened, which policies evaluated, and what the evidence supports.',
      'CONDITIONAL ACCESS · INVESTIGATION',
      exportActions(),
    ) +
    searchbar() +
    metrics() +
    warningsMarkup() +
    evidenceBanner() +
    `<div class="investigation-grid"><div>${timeline()}<section class="panel event-panel"><div class="panel-heading"><div class="panel-title-row"><h2>Sign-in events</h2><span class="count-badge">${num(state.data?.events?.length)}</span></div><button class="text-link" data-action="hunt-user">Open in hunt builder ${icon('arrow')}</button></div>${eventTable()}</section></div>${detailPanel()}</div>`;
}
function fieldOptions(value) {
  return fields
    .map(
      (field) =>
        `<option value="${field}" ${field === value ? 'selected' : ''}>${esc(fieldLabels[field])}</option>`,
    )
    .join('');
}
function filterRows() {
  return state.spec.filters
    .map(
      (filter, index) =>
        `<div class="filter-row" draggable="true" data-filter-index="${index}"><span class="drag-handle" aria-label="Drag to reorder">⠿</span><select data-filter-prop="field" aria-label="Filter ${index + 1} field">${fieldOptions(filter.field)}</select><select data-filter-prop="operator" aria-label="Filter ${index + 1} operator">${Object.entries(
          operators,
        )
          .filter(([op]) =>
            filter.field === 'IsInteractive'
              ? ['eq', 'neq'].includes(op)
              : op !== 'cidr' || filter.field === 'IPAddress',
          )
          .map(
            ([key, label]) =>
              `<option value="${key}" ${filter.operator === key ? 'selected' : ''}>${label}</option>`,
          )
          .join(
            '',
          )}</select><input data-filter-prop="value" value="${esc(Array.isArray(filter.value) ? filter.value.join(', ') : filter.value)}" aria-label="Filter ${index + 1} value" placeholder="${filter.operator === 'in' ? 'Comma-separated values' : 'Value'}"><div class="filter-row-actions"><button class="icon-button" data-filter-action="up" aria-label="Move filter ${index + 1} up" ${index === 0 ? 'disabled' : ''}>↑</button><button class="icon-button" data-filter-action="down" aria-label="Move filter ${index + 1} down" ${index === state.spec.filters.length - 1 ? 'disabled' : ''}>↓</button><button class="icon-button" data-filter-action="remove" aria-label="Remove filter ${index + 1}">×</button></div></div>`,
    )
    .join('');
}
function queryToolbar() {
  const spec = state.spec;
  return `<div class="builder-toolbar">${spec.preset === 'user' ? `<label class="form-field">User principal name<input data-spec="user" value="${esc(spec.user)}" placeholder="alex.morgan@example.com"></label>` : spec.preset === 'ip' ? `<label class="form-field">IP address<input data-spec="ip" value="${esc(spec.ip)}" placeholder="198.51.100.24"></label><label class="form-field">CIDR range<input data-spec="cidr" value="${esc(spec.cidr)}" placeholder="198.51.100.0/24"></label>` : '<div class="form-field"><label>Scope</label><span class="small muted">All identities in the selected source</span></div>'}<label class="form-field compact">Lookback<select data-spec="hours">${[
    [1, 'Last hour'],
    [6, 'Last 6 hours'],
    [24, 'Last 24 hours'],
    [72, 'Last 3 days'],
    [168, 'Last 7 days'],
    [720, 'Last 30 days'],
  ]
    .map(
      ([value, label]) =>
        `<option value="${value}" ${Number(spec.hours) === value ? 'selected' : ''}>${label}</option>`,
    )
    .join('')}</select></label><label class="form-field compact">Return<select data-spec="mode">${[
    ['events', 'Events'],
    ['distinct', 'Distinct values'],
    ['patterns', 'Patterns'],
  ]
    .map(
      ([value, label]) =>
        `<option value="${value}" ${spec.mode === value ? 'selected' : ''}>${label}</option>`,
    )
    .join(
      '',
    )}</select></label><label class="form-field compact">Row limit<input type="number" min="1" max="10000" data-spec="limit" value="${esc(spec.limit)}"></label></div>`;
}
function renderHunt() {
  main.innerHTML =
    heading(
      'KQL hunt builder',
      'Build readable KQL, inspect every condition, and run it against your workspace.',
      'IDENTITY HUNTING · QUERY BUILDER',
      `<span class="pill neutral">Read-only queries</span>`,
    ) +
    `<div class="hunt-layout"><aside class="panel hunt-library"><h3>START WITH A QUESTION</h3>${templates.map((template) => `<button class="template-button ${state.spec.preset === template.id ? 'active' : ''}" data-template="${template.id}">${icon(template.icon)}<span><strong>${template.title}</strong><small>${template.description}</small></span></button>`).join('')}<div class="library-divider"></div><h3>FILTER BLOCKS</h3>${['UserPrincipalName', 'IPAddress', 'AppDisplayName', 'ConditionalAccessStatus', 'RiskLevelDuringSignIn', 'IsInteractive'].map((field) => `<div class="field-chip" draggable="true" data-drag-field="${field}"><span>${fieldLabels[field]}</span><button data-add-field="${field}" aria-label="Add ${fieldLabels[field]} filter">+</button></div>`).join('')}<p class="muted small no-margin">Drag a block into the query, or use + to add it.</p></aside><div><section class="panel"><div class="panel-heading"><div><h2>${esc(templates.find((t) => t.id === state.spec.preset)?.title || 'Custom query')}</h2><p>SigninLogs + AADNonInteractiveUserSignInLogs</p></div><span class="count-badge">KQL</span></div>${queryToolbar()}<div class="filter-zone" id="filter-zone"><div class="query-section-label">FILTER CONDITIONS · MATCH ALL<button class="text-link" data-add-field="AppDisplayName">+ Add condition</button></div><div id="filter-rows">${filterRows()}</div><div class="drop-hint">${icon('filter')} Drop a filter block here</div></div><div class="filter-note">Conditions use AND. “Is one of” accepts a comma-separated list.</div><div class="query-code-header"><span>GENERATED QUERY <span aria-hidden="true">/</span> ${esc(state.spec.mode.toUpperCase())}</span><div class="heading-actions"><button class="button" data-action="copy-query">${icon('copy')}Copy</button><button class="button" data-action="download-query">${icon('download')}.kql</button></div></div><pre class="query-code" id="query-code" aria-label="Generated KQL query">${esc(state.query || 'Building query…')}</pre><div id="query-warnings"></div><div class="query-actions"><p>Generated from allowlisted fields and operators.<br>${['demo', 'offline'].includes(state.source) ? 'Preview filters the loaded evidence timeframe; aggregations run in Log Analytics.' : 'Live execution uses the configured Log Analytics workspace.'}</p><button class="button primary" data-action="run-query">${icon('play')}${['demo', 'offline'].includes(state.source) ? 'Preview loaded evidence' : 'Run in Log Analytics'}</button></div></section><div id="query-results">${queryResultsMarkup()}</div></div></div>`;
  renderQueryWarnings();
  scheduleBuild(0);
}
function renderQueryWarnings() {
  const target = document.querySelector('#query-warnings');
  if (target)
    target.innerHTML = state.queryWarnings?.length
      ? `<div class="warning-strip" style="margin:12px 18px">${state.queryWarnings.map((w) => esc(typeof w === 'string' ? w : w.message || JSON.stringify(w))).join('<br>')}</div>`
      : '';
}
function queryResultsMarkup() {
  if (state.queryError)
    return `<div class="panel query-results"><div class="query-result-error">${esc(state.queryError)}</div></div>`;
  const result = state.queryResult;
  if (!result) return '';
  const tables = result.tables || [];
  let content = '';
  if (tables.length) {
    content = tables
      .map(
        (table) =>
          `<div class="table-scroll"><table><thead><tr>${(table.columns || []).map((col) => `<th>${esc(col.name || col)}</th>`).join('')}</tr></thead><tbody>${(
            table.rows || []
          )
            .slice(0, 100)
            .map(
              (row) =>
                `<tr>${row.map((value) => `<td>${esc(typeof value === 'object' ? JSON.stringify(value) : value)}</td>`).join('')}</tr>`,
            )
            .join('')}</tbody></table></div>`,
      )
      .join('');
  } else if (result.events) content = eventTable(result.events, { paginate: false });
  else if (result.rows?.length) {
    const keys = Object.keys(result.rows[0]);
    content = `<div class="table-scroll"><table><thead><tr>${keys.map((key) => `<th>${esc(key)}</th>`).join('')}</tr></thead><tbody>${result.rows
      .slice(0, 100)
      .map(
        (row) =>
          `<tr>${keys.map((key) => `<td>${esc(typeof row[key] === 'object' ? JSON.stringify(row[key]) : row[key])}</td>`).join('')}</tr>`,
      )
      .join('')}</tbody></table></div>`;
  } else content = emptyState('No query results', 'The query completed without matching rows.');
  const warnings = [...(result.warnings || []), ...(result.metadata?.warnings || [])];
  return `<section class="panel query-results"><div class="panel-heading"><h2>Query results</h2><span class="source-badge">${esc(sourceNames[result.metadata?.source || state.source] || 'Query result')}</span></div><div class="results-summary">${num(result.events?.length || tables.reduce((sum, t) => sum + (t.rows?.length || 0), 0) || result.rows?.length)} rows returned${result.metadata?.truncated ? ' · Row limit reached' : ''}</div>${warnings.length ? `<div class="warning-strip">${warnings.map((w) => esc(typeof w === 'string' ? w : w.message)).join('<br>')}</div>` : ''}${content}</section>`;
}
function scheduleBuild(delay = 250) {
  clearTimeout(buildTimer);
  buildTimer = setTimeout(buildQuery, delay);
}
function pollAuthentication() {
  clearInterval(authPoll);
  authPoll = setInterval(async () => {
    try {
      state.auth = await api('/api/auth/status');
      let node = document.querySelector('#auth-state');
      if (!node && state.view === 'hunt') {
        node = document.createElement('div');
        node.id = 'auth-state';
        document.querySelector('#query-results')?.before(node);
      }
      if (node) node.innerHTML = authMarkup();
      if (
        ['authenticated', 'ready', 'success', 'failed', 'error'].includes(state.auth.status) ||
        state.auth.error
      )
        clearInterval(authPoll);
    } catch (error) {
      clearInterval(authPoll);
      toast(error.message, true);
    }
  }, 1200);
}
async function buildQuery() {
  const sequence = ++state.building;
  try {
    const result = await api('/api/query/build', { spec: state.spec });
    if (sequence !== state.building) return;
    state.query = result.query;
    state.queryWarnings = result.warnings || [];
    const code = document.querySelector('#query-code');
    if (code) code.textContent = state.query;
    renderQueryWarnings();
  } catch (error) {
    if (sequence !== state.building) return;
    state.query = '';
    state.queryWarnings = [error.message];
    const code = document.querySelector('#query-code');
    if (code) code.textContent = 'Complete the query inputs to generate KQL.';
    renderQueryWarnings();
  }
}
function signalChart() {
  const spikes = state.data?.analysis?.spikes || {};
  const bins = spikes.bins || [];
  if (!bins.length)
    return emptyState('No signal window', 'Collect or import sign-ins to compare failure rates.');
  const width = 760,
    height = 215,
    max = Math.max(1, ...bins.map((bin) => bin.total)),
    barWidth = Math.max(2, Math.min(28, 640 / bins.length - 5));
  return `<div class="chart-area"><svg viewBox="0 0 ${width} ${height}" class="signal-chart" role="img" aria-label="Sign-in volume and Conditional Access failures by time bin">${[0, 0.25, 0.5, 0.75, 1].map((t) => `<path d="M40 ${175 - t * 140}H740" stroke="#e6eddb" stroke-dasharray="3 5"/><text x="30" y="${179 - t * 140}" text-anchor="end">${Math.round(max * t)}</text>`).join('')}${bins
    .map((bin, index) => {
      const x = 51 + ((index + 0.5) * 680) / bins.length,
        barHeight = (bin.total / max) * 140,
        failHeight = (bin.caFailures / max) * 140;
      return `<g><title>${esc(`${date(bin.timestamp)} ${time(bin.timestamp)} UTC: ${bin.total} sign-ins, ${bin.caFailures} CA failures, ${pct(bin.rate)} failure rate`)}</title><rect class="bar" x="${x - barWidth / 2}" y="${175 - barHeight}" width="${barWidth}" height="${barHeight}" rx="2"/><rect class="bar-fail" x="${x - barWidth / 2}" y="${175 - failHeight}" width="${barWidth}" height="${failHeight}" rx="2"/>${index % Math.max(1, Math.ceil(bins.length / 7)) === 0 ? `<text x="${x}" y="195" text-anchor="middle">${time(bin.timestamp).slice(0, 5)}</text>` : ''}</g>`;
    })
    .join('')}</svg></div>`;
}
function renderSignals() {
  const analysis = state.data?.analysis || {},
    spikes = analysis.spikes || {},
    findings = analysis.findings || [],
    policies = analysis.policies || [];
  main.innerHTML =
    heading(
      'Conditional Access signals',
      'Separate recurring enforcement from isolated failures, using the evidence you collected.',
      'CONDITIONAL ACCESS · SIGNALS',
      `<button class="button" data-action="spike-hunt">${icon('hunt')}Hunt spikes</button>`,
    ) +
    `<div class="warning-strip">Scope: ${esc(state.user || 'all identities')} · ${num(state.data?.events?.length)} collected events. Signals describe this evidence set, not tenant-wide prevalence.</div>` +
    metrics() +
    warningsMarkup() +
    `<div class="signals-grid"><section class="panel"><div class="panel-heading"><div><h2>Enforcement over time</h2><p>Sign-in volume with CA failures highlighted</p></div><span class="pill neutral">${pct(spikes.baselineRate)} baseline</span></div><div class="timeline-legend"><span class="legend-item"><span class="dot"></span>All sign-ins</span><span class="legend-item"><span class="dot red"></span>CA failures</span><span class="legend-item">${num(spikes.candidates?.length)} elevated bins</span></div>${signalChart()}<div class="chart-footnote">${esc(spikes.caveat || 'A high failure rate is an investigation lead. Confirm volume, completeness, and the selected time window before calling an incident.')}</div></section><section class="panel"><div class="panel-heading"><h2>Evidence observations</h2><span class="count-badge">${num(findings.length)}</span></div>${
      findings.length
        ? findings
            .slice(0, 6)
            .map(
              (f) =>
                `<div class="finding-item ${f.severity === 'info' ? 'info' : ''}"><span class="finding-icon">${icon(f.severity === 'info' ? 'info' : 'alert')}</span><div><h3>${esc(f.title)}</h3><p>${esc(f.detail)}</p>${f.eventIds?.length ? `<button class="text-link" data-finding-event="${esc(f.eventIds[0])}">Inspect evidence →</button>` : ''}</div></div>`,
            )
            .join('')
        : emptyState('No observations yet', 'Import sign-in evidence to start analyzing.')
    }</section></div><section class="panel policy-summary"><div class="panel-heading"><div><h2>Policy outcomes</h2><p>Enforced and report-only results are counted separately</p></div><span class="count-badge">${num(policies.length)} policies</span></div>${policies.length ? `<div class="table-scroll"><table><thead><tr><th>Policy</th><th>Evaluations</th><th>Satisfied</th><th>Failed</th><th>Report-only failed</th><th>Not applied</th><th>Outcome mix</th></tr></thead><tbody>${policies.map((policy) => `<tr><td><span class="cell-main">${esc(policy.displayName || policy.id)}</span></td><td>${num(policy.total)}</td><td>${num(policy.success)}</td><td><span class="${policy.failure ? 'pill fail' : ''}">${num(policy.failure)}</span></td><td>${num(policy.reportOnlyFailure)}</td><td>${num(policy.notApplied)}</td><td><div class="progress-track" aria-label="Policy result proportions"><span class="progress-success" style="width:${((policy.success || 0) / Math.max(policy.total, 1)) * 100}%"></span><span class="progress-fail" style="width:${((policy.failure || 0) / Math.max(policy.total, 1)) * 100}%"></span><span class="progress-report" style="width:${((policy.reportOnlyFailure || 0) / Math.max(policy.total, 1)) * 100}%"></span></div></td></tr>`).join('')}</tbody></table></div>` : emptyState('No policy details available', 'Missing policy evidence does not mean no policies applied.')}</section><div class="context-note spacer-top">${(analysis.caveats || []).map(esc).join('<br>') || 'Policy intent and incident-time configuration must be reviewed separately from observed sign-in outcomes.'}</div>`;
}
function renderConnections() {
  const c = state.config,
    modes = [
      ['azure-cli', 'Analyst account', 'Uses your existing Azure CLI sign-in.'],
      ['device-code', 'Delegated app', 'Uses your tenant and public client app.'],
      ['client-secret', 'App registration', 'Reads a secret from the server environment.'],
      ['managed-identity', 'Managed identity', 'Uses an identity assigned to the host.'],
    ];
  main.innerHTML =
    heading(
      'Data connections',
      'Connect read-only cloud sources or investigate an exported sign-in dataset.',
      'WORKSPACE · CONNECTIONS',
      `<span class="pill">${icon('lock')}Local session</span>`,
    ) +
    `<div class="connections-grid"><section class="panel connection-card"><div class="connection-title"><span class="connection-symbol">${icon('connections')}</span><div><h2>Cloud sources</h2><span class="small">Microsoft Graph + Log Analytics / Sentinel</span></div></div><p>Collect both interactive and non-interactive sign-ins within a bounded time window. Cloud requests run from the local backend.</p><form id="collect-form"><label class="form-field">Data source<select name="source"><option value="graph">Microsoft Graph · sign-in logs</option><option value="log-analytics">Log Analytics / Microsoft Sentinel</option></select></label><label class="form-field">User principal name<input name="user" value="${esc(state.user)}" placeholder="alex.morgan@example.com" autocomplete="off"></label><div style="display:flex;gap:12px"><label class="form-field">From · UTC<input name="start" type="datetime-local" required value="${esc(state.start || new Date(Date.now() - 86400000).toISOString().slice(0, 16))}"></label><label class="form-field">To · UTC<input name="end" type="datetime-local" required value="${esc(state.end || new Date().toISOString().slice(0, 16))}"></label></div><label class="form-field">Log Analytics workspace ID<input name="workspaceId" value="${esc(c.workspaceId || '')}" placeholder="Workspace GUID · required for Log Analytics" autocomplete="off"></label><div class="connection-actions"><button class="button primary" type="submit">${icon('download')}Collect sign-ins</button><button class="button" type="button" data-action="auth-login">${icon('user')}Check / start authentication</button></div></form><div id="auth-state">${authMarkup()}</div><div class="context-note">Graph non-interactive collection uses the beta sign-in endpoint. The app surfaces coverage limits and permission failures instead of treating missing evidence as success.</div></section><section class="panel connection-card"><div class="connection-title"><span class="connection-symbol">${icon('shield')}</span><div><h2>Authentication & guardrails</h2><span class="small">Configured on the server · no secrets in the browser</span></div></div><div class="connection-status"><span>Active authentication</span><strong>${esc(c.authMode || 'azure-cli')}</strong></div><div class="connection-status"><span>Tenant ID</span><strong>${esc(c.tenantId || 'Not configured')}</strong></div><div class="connection-status"><span>Client ID</span><strong>${esc(c.clientId || 'Not configured')}</strong></div><div class="auth-modes">${modes.map(([id, title, description]) => `<div class="auth-mode ${(c.authMode || 'azure-cli') === id ? 'configured' : ''}"><strong>${title}</strong><p>${description}</p></div>`).join('')}</div><div class="guardrail">${icon('check')}Read-only source access. No policy changes, user changes, or remediation actions.</div><div class="guardrail">${icon('check')}Credentials remain on the backend. Evidence is held in memory until explicitly exported.</div><div class="guardrail">${icon('check')}Loopback-only server, CSRF-protected requests, and generated queries with bounded inputs.</div><div class="guardrail">${icon('check')}No AI service receives sign-in data. Analysis uses transparent, deterministic rules.</div></section><section class="panel connection-card"><div class="connection-title"><span class="connection-symbol">${icon('upload')}</span><div><h2>Offline evidence</h2><span class="small">No authentication required</span></div></div><p>Import a JSON array, a Microsoft Graph <span class="mono">value</span> response, or a Log Analytics <span class="mono">tables</span> response. Keep the original policy and correlation fields for stronger conclusions.</p><button class="import-zone" id="import-zone" style="width:100%" data-action="import">${icon('upload')}<strong>Choose a sign-in export</strong><small>Or drop a JSON file here · up to 20 MB</small></button><div class="connection-actions"><button class="button" data-action="demo">${icon('flask')}Load synthetic case</button></div><div class="context-note">The demo uses fictional identities and documentation IP ranges. Loading a new dataset replaces the current in-memory case; export evidence first if you need to keep it.</div></section><section class="panel connection-card"><div class="connection-title"><span class="connection-symbol">${icon('terminal')}</span><div><h2>Configure from the terminal</h2><span class="small">Same analysis engine. Your choice of interface.</span></div></div><p>Set the environment before starting Traceglass. The selected authentication provider controls how live data is read.</p><pre class="env-example">TRACEGLASS_AUTH_MODE=azure-cli
TRACEGLASS_TENANT_ID=&lt;tenant-guid&gt;
TRACEGLASS_WORKSPACE_ID=&lt;workspace-guid&gt;

# Dedicated delegated app
TRACEGLASS_AUTH_MODE=device-code
TRACEGLASS_CLIENT_ID=&lt;public-client-guid&gt;

# See docs/CONNECTORS.md for setup,
# permissions, service identities,
# and PowerShell examples.</pre><p class="small no-margin">For an app secret, set <span class="mono">TRACEGLASS_CLIENT_SECRET</span> in the backend environment. Never paste tokens or secrets into this UI.</p></section></div>`;
}
function authMarkup() {
  const auth = state.auth;
  if (!auth) return '';
  if (auth.error) return `<div class="warning-strip spacer-top">${esc(auth.error)}</div>`;
  const challenge = auth.challenge;
  return `<div class="auth-challenge"><strong>${esc(auth.status || 'Authentication')}</strong>${challenge ? `<div class="auth-code">${esc(challenge.userCode)}</div><p>${esc(challenge.message || 'Complete authentication in your browser.')}</p>${/^https:\/\/(microsoft\.com|www\.microsoft\.com|login\.microsoftonline\.com)\//i.test(challenge.verificationUri || '') ? `<a href="${esc(challenge.verificationUri)}" target="_blank" rel="noopener noreferrer">Open Microsoft authentication ↗</a>` : ''}` : auth.message ? `<p>${esc(auth.message)}</p>` : ''}</div>`;
}
function render() {
  updateChrome();
  (
    ({
      investigate: renderInvestigation,
      hunt: renderHunt,
      signals: renderSignals,
      connections: renderConnections,
    })[state.view] || renderInvestigation
  )();
}
function navigate(view) {
  state.view = ['investigate', 'hunt', 'signals', 'connections'].includes(view)
    ? view
    : 'investigate';
  if (location.hash !== `#${state.view}`) history.replaceState(null, '', `#${state.view}`);
  render();
  window.scrollTo({ top: 0, behavior: 'instant' });
}
async function importFile(file) {
  if (!file) return;
  if (file.size > 20 * 1024 * 1024) {
    toast('This export is larger than 20 MB. Split it into smaller evidence windows.', true);
    return;
  }
  try {
    const data = JSON.parse(await file.text());
    const result = await api('/api/import', { data });
    state.user = '';
    state.start = '';
    state.end = '';
    state.interaction = 'all';
    state.source = 'offline';
    setData(result);
    navigate('investigate');
    toast('Evidence imported. The current case is held in memory.');
  } catch (error) {
    toast(`Import failed: ${error.message}`, true);
  } finally {
    document.querySelector('#file-import').value = '';
  }
}
async function loadDemo() {
  try {
    state.source = 'demo';
    state.user = 'alex.morgan@example.com';
    state.start = '';
    state.end = '';
    state.interaction = 'all';
    state.selected = null;
    await api('/api/demo', {});
    setData(await api(`/api/investigation?${investigationParams()}`));
    navigate('investigate');
    toast('Synthetic case loaded. These are fictional sign-ins.');
  } catch (error) {
    toast(error.message, true);
  }
}
function download(content, name, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function addFilter(field) {
  state.spec.filters.push({
    field,
    operator: 'eq',
    value: field === 'IsInteractive' ? 'false' : '',
  });
  const rows = document.querySelector('#filter-rows');
  if (rows) rows.innerHTML = filterRows();
  scheduleBuild();
}

document.querySelector('#navigation').innerHTML = [
  ['investigate', 'investigate', 'Investigate'],
  ['hunt', 'hunt', 'Hunt builder'],
  ['signals', 'signals', 'Signals'],
  ['connections', 'connections', 'Connections'],
]
  .map(
    ([view, i, label]) =>
      `<a class="nav-item" href="#${view}" data-view="${view}" title="${label}"><span class="nav-icon">${icon(i)}</span><span>${label}</span></a>`,
  )
  .join('');
document.querySelectorAll('[data-icon]').forEach((el) => {
  el.innerHTML = icon(el.dataset.icon);
});
document.querySelector('#navigation').addEventListener('click', (event) => {
  const target = event.target.closest('[data-view]');
  if (target) {
    event.preventDefault();
    navigate(target.dataset.view);
  }
});
document.querySelector('#load-demo').addEventListener('click', loadDemo);
document
  .querySelector('#sidebar-import')
  .addEventListener('click', () => document.querySelector('#file-import').click());
document
  .querySelector('#file-import')
  .addEventListener('change', (event) => importFile(event.target.files[0]));
document
  .querySelector('#keyboard-help')
  .addEventListener('click', () => document.querySelector('#help-dialog').showModal());
document
  .querySelector('.dialog-close')
  .addEventListener('click', () => document.querySelector('#help-dialog').close());
window.addEventListener('hashchange', () => navigate(location.hash.slice(1)));
document.addEventListener('keydown', (event) => {
  if (
    ['INPUT', 'SELECT', 'TEXTAREA'].includes(event.target.tagName) ||
    event.ctrlKey ||
    event.metaKey ||
    event.altKey ||
    document.querySelector('#help-dialog').open
  )
    return;
  if (event.key === '/') {
    event.preventDefault();
    if (state.view !== 'investigate') navigate('investigate');
    document.querySelector('#user-search')?.focus();
  }
  if (['1', '2', '3', '4'].includes(event.key))
    navigate(['investigate', 'hunt', 'signals', 'connections'][Number(event.key) - 1]);
});
main.addEventListener('keydown', (event) => {
  const target = event.target.closest('[data-event]');
  if (target && ['Enter', ' '].includes(event.key)) {
    event.preventDefault();
    target.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  }
});
main.addEventListener('click', async (event) => {
  const target = event.target.closest('button,[data-event],[data-finding-event]');
  if (!target) return;
  try {
    if (target.dataset.event) {
      if (state.data?.events?.some((e) => e.id === target.dataset.event)) {
        state.selected = target.dataset.event;
        state.detailTab = 'evidence';
        if (state.view !== 'investigate') navigate('investigate');
        else renderInvestigation();
      } else
        toast(
          'This query row is outside the current investigation. Search its user to inspect the full case.',
        );
      return;
    }
    if (target.dataset.findingEvent) {
      state.selected = target.dataset.findingEvent;
      navigate('investigate');
      return;
    }
    if (target.dataset.interaction) {
      state.interaction = target.dataset.interaction;
      await loadInvestigation();
      return;
    }
    if (target.dataset.detailTab) {
      state.detailTab = target.dataset.detailTab;
      renderInvestigation();
      return;
    }
    if (target.dataset.template) {
      const preset = target.dataset.template;
      state.spec = {
        preset,
        user: preset === 'user' ? state.user : '',
        ip: preset === 'ip' ? '198.51.100.24' : '',
        cidr: '',
        hours: 24,
        limit: 500,
        mode: preset === 'patterns' ? 'patterns' : 'events',
        filters: [],
      };
      state.queryResult = null;
      state.queryError = '';
      renderHunt();
      return;
    }
    if (target.dataset.addField) {
      addFilter(target.dataset.addField);
      return;
    }
    if (target.dataset.filterAction) {
      const index = Number(target.closest('[data-filter-index]').dataset.filterIndex),
        action = target.dataset.filterAction;
      if (action === 'remove') state.spec.filters.splice(index, 1);
      else {
        const next = index + (action === 'up' ? -1 : 1);
        [state.spec.filters[index], state.spec.filters[next]] = [
          state.spec.filters[next],
          state.spec.filters[index],
        ];
      }
      document.querySelector('#filter-rows').innerHTML = filterRows();
      scheduleBuild();
      return;
    }
    const action = target.dataset.action;
    if (action === 'import') document.querySelector('#file-import').click();
    if (action === 'toggle-export') {
      const menu = target.nextElementSibling;
      menu.hidden = !menu.hidden;
      target.setAttribute('aria-expanded', String(!menu.hidden));
    }
    if (action === 'view-signals') navigate('signals');
    if (action === 'hunt-user') {
      state.spec.preset = 'user';
      state.spec.user = state.user;
      state.queryResult = null;
      state.queryError = '';
      navigate('hunt');
    }
    if (action === 'spike-hunt') {
      state.spec.preset = 'spikes';
      state.spec.mode = 'events';
      state.queryResult = null;
      state.queryError = '';
      navigate('hunt');
    }
    if (action === 'previous-page') {
      state.page--;
      renderInvestigation();
    }
    if (action === 'next-page') {
      state.page++;
      renderInvestigation();
    }
    if (action === 'copy-query') {
      await buildQuery();
      if (!state.query) throw new Error('Complete the query inputs before copying.');
      await navigator.clipboard.writeText(state.query);
      toast('KQL copied to the clipboard.');
    }
    if (action === 'download-query') {
      await buildQuery();
      if (!state.query) throw new Error('Complete the query inputs before downloading.');
      download(state.query, `traceglass-${state.spec.preset}.kql`);
    }
    if (action === 'run-query') {
      target.disabled = true;
      target.innerHTML = `${icon('refresh')}Running…`;
      state.queryError = '';
      if (state.config.authMode === 'device-code' && !['demo', 'offline'].includes(state.source))
        pollAuthentication();
      try {
        const result = await api('/api/query/run', {
          spec: state.spec,
          source: ['demo', 'offline'].includes(state.source) ? state.source : 'log-analytics',
          workspaceId: state.config.workspaceId,
        });
        state.queryResult = result;
        state.query = result.query || state.query;
      } catch (error) {
        state.queryError = error.message;
        state.queryResult = null;
      } finally {
        clearInterval(authPoll);
        const resultNode = document.querySelector('#query-results');
        if (resultNode) resultNode.innerHTML = queryResultsMarkup();
        target.disabled = false;
        target.innerHTML = `${icon('play')}${['demo', 'offline'].includes(state.source) ? 'Preview loaded evidence' : 'Run in Log Analytics'}`;
      }
    }
    if (action === 'demo') await loadDemo();
    if (action === 'auth-login') {
      target.disabled = true;
      try {
        state.auth = await api('/api/auth/login', {
          source: document.querySelector('#collect-form select[name="source"]')?.value || 'graph',
        });
        document.querySelector('#auth-state').innerHTML = authMarkup();
        pollAuthentication();
      } finally {
        target.disabled = false;
      }
    }
  } catch (error) {
    toast(error.message, true);
  }
});
main.addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = new FormData(event.target);
  if (event.target.id === 'investigation-search') {
    state.user = String(data.get('user') || '');
    state.start = String(data.get('start') || '');
    state.end = String(data.get('end') || '');
    await loadInvestigation();
  }
  if (event.target.id === 'collect-form') {
    const button = event.target.querySelector('button[type="submit"]');
    button.disabled = true;
    button.innerHTML = `${icon('refresh')}Collecting…`;
    state.config.workspaceId = String(data.get('workspaceId') || '');
    if (state.config.authMode === 'device-code') pollAuthentication();
    try {
      const source = String(data.get('source'));
      const result = await api('/api/collect', {
        source,
        user: String(data.get('user') || ''),
        start: isoField(String(data.get('start'))),
        end: isoField(String(data.get('end'))),
        workspaceId: state.config.workspaceId,
      });
      state.user = String(data.get('user') || '');
      state.start = String(data.get('start'));
      state.end = String(data.get('end'));
      state.interaction = 'all';
      state.source = source;
      setData(result);
      navigate('investigate');
      toast('Sign-ins collected. Review the coverage notes with your findings.');
    } catch (error) {
      toast(error.message, true);
    } finally {
      clearInterval(authPoll);
      button.disabled = false;
      button.innerHTML = `${icon('download')}Collect sign-ins`;
    }
  }
});
main.addEventListener('input', (event) => {
  if (event.target.dataset.spec) {
    const key = event.target.dataset.spec;
    state.spec[key] = ['hours', 'limit'].includes(key)
      ? Number(event.target.value)
      : event.target.value;
    scheduleBuild();
  }
  if (event.target.dataset.filterProp) {
    const row = event.target.closest('[data-filter-index]'),
      filter = state.spec.filters[Number(row.dataset.filterIndex)],
      prop = event.target.dataset.filterProp;
    filter[prop] = event.target.value;
    if (prop === 'field') {
      if (filter.field === 'IsInteractive') {
        filter.operator = 'eq';
        filter.value = 'false';
      } else if (filter.field !== 'IPAddress' && filter.operator === 'cidr') filter.operator = 'eq';
      document.querySelector('#filter-rows').innerHTML = filterRows();
    }
    scheduleBuild();
  }
});
main.addEventListener('dragstart', (event) => {
  const field = event.target.closest('[data-drag-field]'),
    row = event.target.closest('[data-filter-index]');
  if (field) {
    state.drag = { field: field.dataset.dragField };
    event.dataTransfer.setData('text/plain', field.dataset.dragField);
  } else if (row) {
    state.drag = { index: Number(row.dataset.filterIndex) };
    event.dataTransfer.setData('text/plain', 'reorder');
  } else return;
  event.dataTransfer.effectAllowed = 'copyMove';
});
main.addEventListener('dragover', (event) => {
  const zone = event.target.closest('#filter-zone,#import-zone');
  if (zone) {
    event.preventDefault();
    zone.classList.add('drag-over');
    event.dataTransfer.dropEffect =
      zone.id === 'import-zone' ? 'copy' : state.drag?.field ? 'copy' : 'move';
  }
});
main.addEventListener('dragleave', (event) => {
  const zone = event.target.closest('#filter-zone,#import-zone');
  if (zone && !zone.contains(event.relatedTarget)) zone.classList.remove('drag-over');
});
main.addEventListener('drop', (event) => {
  const zone = event.target.closest('#filter-zone,#import-zone');
  if (!zone) return;
  event.preventDefault();
  zone.classList.remove('drag-over');
  if (zone.id === 'import-zone') {
    importFile(event.dataTransfer.files[0]);
    return;
  }
  if (state.drag?.field) addFilter(state.drag.field);
  else if (state.drag?.index != null) {
    const row = event.target.closest('[data-filter-index]');
    const next = row ? Number(row.dataset.filterIndex) : state.spec.filters.length - 1;
    const [item] = state.spec.filters.splice(state.drag.index, 1);
    state.spec.filters.splice(next, 0, item);
    document.querySelector('#filter-rows').innerHTML = filterRows();
    scheduleBuild();
  }
  state.drag = null;
});
main.addEventListener('dragend', () => {
  state.drag = null;
  document.querySelectorAll('.drag-over').forEach((el) => el.classList.remove('drag-over'));
});

async function init() {
  try {
    const session = await api('/api/session');
    state.csrfToken = session.csrfToken;
    state.config = session.config || {};
    state.source = session.source || 'demo';
    if (state.source !== 'demo') state.user = '';
    setData(await api(`/api/investigation?${investigationParams()}`));
    navigate(location.hash.slice(1) || 'investigate');
  } catch (error) {
    main.innerHTML = `<div class="error-page"><div class="eyebrow">WORKSPACE UNAVAILABLE</div><h1>Could not load the evidence.</h1><p>${esc(error.message)}</p><button class="button primary" id="retry-init">Try again</button><p>Start the local server, then open its loopback URL.</p></div>`;
    document.querySelector('#retry-init').addEventListener('click', init);
    toast(error.message, true);
  }
}
init();
