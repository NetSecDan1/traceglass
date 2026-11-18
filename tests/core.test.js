import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { normalizeEvents } from '../src/core/normalize.js';
import { analyze } from '../src/core/analyze.js';
import { buildKql, filterEvents, validateCidr } from '../src/core/kql.js';

const record = (changes = {}) => ({
  id: 'a',
  createdDateTime: '2026-11-16T09:30:00Z',
  userPrincipalName: 'alex@example.com',
  appDisplayName: 'Office',
  isInteractive: true,
  status: { errorCode: 0 },
  conditionalAccessStatus: 'success',
  appliedConditionalAccessPolicies: [],
  ...changes,
});

test('Graph and LA records preserve policy visibility, event-time and dynamic details', () => {
  const [event] = normalizeEvents({
    tables: [
      {
        name: 'PrimaryResult',
        columns: [
          'Id',
          'CreatedDateTime',
          'TimeGenerated',
          'UserPrincipalName',
          'ResultType',
          'ConditionalAccessPolicies',
          'DeviceDetail',
          'AuthenticationDetails',
          'SourceTable',
        ].map((name) => ({ name })),
        rows: [
          [
            'la',
            '2026-11-16T09:00:00Z',
            '2026-11-16T09:10:00Z',
            'a@example.com',
            '53000',
            '[{"id":"p","displayName":"Compliance","result":"failure","enforcedGrantControls":["CompliantDevice"]}]',
            '{"isCompliant":false}',
            '[{"succeeded":false}]',
            'AADNonInteractiveUserSignInLogs',
          ],
        ],
      },
    ],
  });
  assert.equal(event.timestamp, '2026-11-16T09:00:00.000Z');
  assert.equal(event.isInteractive, false);
  assert.equal(event.status.errorCode, 53000);
  assert.equal(event.device.isCompliant, false);
  assert.equal(event.policyVisibility, 'available');
  assert.equal(event.policies[0].result, 'failure');
  assert.equal(event.authenticationDetails[0].succeeded, false);
});

test('missing policy details differ from an explicit empty array', () => {
  const missing = record({ appliedConditionalAccessPolicies: undefined });
  const events = normalizeEvents([missing, record({ id: 'b' })]);
  assert.deepEqual(
    events.map((e) => e.policyVisibility),
    ['missing', 'available'],
  );
  assert.equal(analyze(events).coverage.policyDetailsMissing, 1);
});

test('missing or invalid status is unknown, never implicitly successful', () => {
  const events = normalizeEvents([
    record({ status: {} }),
    record({ id: 'b', status: { errorCode: 'bad' } }),
  ]);
  assert.equal(analyze(events).summary.unknown, 2);
  assert.equal(analyze(events).summary.successes, 0);
});

test('boolean, array and blank error codes do not fabricate success', () => {
  const events = normalizeEvents(
    [false, [], {}, '   ', -1, '1.5'].map((errorCode, i) =>
      record({ id: String(i), status: { errorCode } }),
    ),
  );
  assert.equal(analyze(events).summary.successes, 0);
  assert.equal(analyze(events).summary.unknown, 6);
});

test('report-only failure cannot be attributed as enforcement', () => {
  const result = analyze(
    normalizeEvents([
      record({
        appliedConditionalAccessPolicies: [
          { id: 'p', displayName: 'Pilot', result: 'reportOnlyFailure' },
        ],
      }),
    ]),
  );
  assert.equal(result.summary.caFailures, 0);
  assert.equal(result.summary.reportOnlyFailures, 1);
  assert.equal(result.summary.successes, 1);
  assert.ok(!result.findings.some((f) => f.id === 'ca-enforced'));
});

test('CA success does not override an authentication failure', () => {
  const result = analyze(
    normalizeEvents([record({ status: { errorCode: 50126, failureReason: 'Invalid password' } })]),
  );
  assert.equal(result.summary.failures, 1);
  assert.equal(result.summary.caFailures, 0);
  assert.ok(result.findings.some((f) => f.id === 'other-failures'));
});

test('contradictory success and policy failure require review', () => {
  const result = analyze(
    normalizeEvents([
      record({ appliedConditionalAccessPolicies: [{ id: 'p', result: 'failure' }] }),
    ]),
  );
  assert.ok(result.findings.some((f) => f.id === 'ca-outcome-conflict'));
  assert.ok(!result.findings.some((f) => f.id === 'ca-enforced'));
});

test('nearby interactive and noninteractive records are context, not a proven session', () => {
  const events = normalizeEvents([
    record(),
    record({
      id: 'b',
      createdDateTime: '2026-11-16T09:32:00Z',
      isInteractive: false,
      status: { errorCode: 53003 },
      conditionalAccessStatus: 'failure',
    }),
  ]);
  const result = analyze(events);
  assert.equal(result.links[0].strength, 'context');
  assert.equal(result.links[0].deltaSeconds, 120);
  assert.ok(result.findings.some((f) => f.id === 'interactive-divergence'));
});

test('matching original request associates events but preserves a causality caveat', () => {
  const result = analyze(
    normalizeEvents([
      record(),
      record({
        id: 'b',
        createdDateTime: '2026-11-16T09:32:00Z',
        originalRequestId: 'a',
        isInteractive: false,
      }),
    ]),
  );
  assert.equal(result.links[0].strength, 'strong');
  assert.match(result.links[0].reason, /association/i);
});

test('shared identifiers across different users never link events', () => {
  const result = analyze(
    normalizeEvents([
      record({ sessionId: 'same', correlationId: 'same' }),
      record({
        id: 'b',
        userPrincipalName: 'other@example.com',
        createdDateTime: '2026-11-16T09:32:00Z',
        sessionId: 'same',
        correlationId: 'same',
      }),
    ]),
  );
  assert.equal(result.links.length, 0);
});

test('temporal context requires same app and a 30 minute window', () => {
  const result = analyze(
    normalizeEvents([
      record(),
      record({
        id: 'b',
        createdDateTime: '2026-11-16T09:31:00Z',
        appDisplayName: 'Another app',
        isInteractive: false,
      }),
      record({ id: 'c', createdDateTime: '2026-11-16T10:01:00Z', isInteractive: false }),
    ]),
  );
  assert.equal(result.links.length, 0);
});

test('missing application identity cannot support a same-application context claim', () => {
  const result = analyze(
    normalizeEvents([
      record({ appDisplayName: undefined }),
      record({
        id: 'b',
        appDisplayName: undefined,
        createdDateTime: '2026-11-16T09:31:00Z',
        isInteractive: false,
        status: { errorCode: 53003 },
        conditionalAccessStatus: 'failure',
      }),
    ]),
  );
  assert.equal(result.links.length, 0);
  assert.ok(!result.findings.some((f) => f.id === 'interactive-divergence'));
});

test('unknown type and ambiguous local timestamp remain explicit gaps', () => {
  const event = normalizeEvents([
    record({ createdDateTime: '2026-11-16T09:30:00', isInteractive: undefined }),
  ])[0];
  assert.equal(event.timestamp, null);
  assert.equal(event.isInteractive, null);
  assert.equal(analyze([event]).spikes.bins.length, 0);
  assert.equal(analyze([event]).coverage.invalidTimestamps, 1);
});

test('duplicate source records prefer available policy evidence', () => {
  const events = normalizeEvents([
    record({ appliedConditionalAccessPolicies: undefined }),
    record({ appliedConditionalAccessPolicies: [{ id: 'p', result: 'success' }] }),
  ]);
  assert.equal(events.length, 1);
  assert.equal(events[0].policies.length, 1);
});

test('contradictory observations retain both originals and an unknown outcome', () => {
  const events = normalizeEvents([
    record(),
    record({ status: { errorCode: 53003 }, conditionalAccessStatus: 'failure' }),
  ]);
  assert.equal(events.length, 1);
  assert.equal(events[0].observations.length, 2);
  assert.equal(events[0].observationConflict, true);
  assert.equal(events[0].status.errorCode, null);
  const result = analyze(events);
  assert.equal(result.summary.successes, 0);
  assert.equal(result.summary.failures, 0);
  assert.equal(result.summary.unknown, 1);
  assert.ok(result.findings.some((f) => f.id === 'conflicting-observations'));
  assert.equal(normalizeEvents(events)[0].observations.length, 2);
});

test('empty data produces no invented spike or success rate', () => {
  const result = analyze([]);
  assert.equal(result.summary.total, 0);
  assert.equal(result.spikes.baselineRate, null);
  assert.deepEqual(result.spikes.candidates, []);
});

test('demo has a representative preceding sample and one failure concentration', async () => {
  const fixture = JSON.parse(
    await readFile(new URL('../fixtures/demo-signins.json', import.meta.url), 'utf8'),
  );
  assert.equal(fixture.synthetic, true);
  const result = analyze(normalizeEvents(fixture));
  assert.equal(result.summary.total, 60);
  assert.equal(result.summary.caFailures, 14);
  assert.equal(result.summary.successes, 45);
  assert.equal(result.spikes.candidates.length, 1);
  assert.equal(result.spikes.candidates[0].caFailures, 12);
});

test('spikes require sufficient prior volume', () => {
  const events = normalizeEvents(
    Array.from({ length: 8 }, (_, i) =>
      record({
        id: String(i),
        createdDateTime: `2026-11-16T09:40:0${i}Z`,
        conditionalAccessStatus: 'failure',
        status: { errorCode: 53003 },
      }),
    ),
  );
  assert.equal(analyze(events).spikes.candidates.length, 0);
});

test('KQL normalizes dynamic columns before combining both sign-in tables', () => {
  const { query } = buildKql({ user: 'a@example.com' });
  assert.match(query, /union isfuzzy=true/);
  assert.match(query, /\(SigninLogs/);
  assert.match(query, /\(AADNonInteractiveUserSignInLogs/);
  assert.equal((query.match(/ConditionalAccessPolicies = parse_json/g) || []).length, 2);
  assert.match(query, /CreatedDateTime/);
});

test('KQL escapes quote, backslash, and newline in user-controlled literal', () => {
  const { query } = buildKql({ user: "alex'\\\n| take 1 //" });
  assert.match(query, /UserPrincipalName =~ 'alex\\'\\\\\\n\| take 1 \/\/'/);
  assert.equal(query.split('\n').filter((line) => line === '| take 1 //').length, 0);
});

test('KQL rejects field and operator injection and resource abuse', () => {
  assert.throws(
    () => buildKql({ filters: [{ field: 'IPAddress | take 1', operator: 'eq', value: 'x' }] }),
    /Unsupported query field/,
  );
  assert.throws(
    () => buildKql({ filters: [{ field: 'IPAddress', operator: 'has_any | take', value: 'x' }] }),
    /Unsupported filter/,
  );
  assert.throws(() => buildKql({ hours: 0 }), /hours/);
  assert.throws(() => buildKql({ limit: 10001 }), /limit/);
  assert.throws(
    () => buildKql({ filters: Array(31).fill({ field: 'UserId', operator: 'eq', value: 'x' }) }),
    /30/,
  );
});

test('KQL validates IPv4 and IPv6 ranges and chooses the correct predicate', () => {
  assert.match(buildKql({ cidr: '192.0.2.0/24' }).query, /ipv4_is_in_range/);
  assert.match(buildKql({ cidr: '2001:db8::/32' }).query, /ipv6_is_in_range/);
  for (const bad of [
    '192.0.2.0/33',
    '2001:db8::/129',
    '192.0.2.0/-1',
    "1.2.3.4/24') | take 1",
    'fe80::1%eth0/64',
  ])
    assert.throws(() => validateCidr(bad));
});

test('boolean filters do not permit expression injection', () => {
  assert.match(
    buildKql({ filters: [{ field: 'IsInteractive', operator: 'eq', value: false }] }).query,
    /IsInteractive == false/,
  );
  assert.throws(
    () =>
      buildKql({ filters: [{ field: 'IsInteractive', operator: 'eq', value: 'false or true' }] }),
    /true\/false/,
  );
});

test('distinct and pattern modes group only on supported fields', () => {
  assert.match(buildKql({ mode: 'distinct', groupBy: ['IPAddress'] }).query, /by IPAddress/);
  const q = buildKql({ mode: 'patterns', groupBy: ['IsInteractive'] }).query;
  assert.ok(!q.includes('by IsInteractive, IsInteractive'));
  assert.throws(() => buildKql({ groupBy: ['x); delete'] }), /groupBy/);
});

test('absolute event-time bounds appear before result limit', () => {
  const query = buildKql({
    start: '2026-11-16T09:00:00-05:00',
    end: '2026-11-16T10:00:00-05:00',
  }).query;
  assert.match(query, /datetime\(2026-11-16T14:00:00.000Z\)/);
  assert.ok(query.indexOf('between') < query.indexOf('| take'));
  assert.throws(
    () => buildKql({ start: '2026-11-16T09:00:00', end: '2026-11-16T10:00:00' }),
    /timezone/,
  );
  assert.throws(
    () => buildKql({ start: '2026-11-16T10:00:00Z', end: '2026-11-16T09:00:00Z' }),
    /increasing/,
  );
});

test('local filtering supports case-insensitive operators and excludes unknown booleans', () => {
  const events = normalizeEvents([
    record(),
    record({ id: 'b', userPrincipalName: 'Bob@example.com', isInteractive: undefined }),
  ]);
  assert.equal(
    filterEvents(events, {
      filters: [{ field: 'UserPrincipalName', operator: 'startsWith', value: 'ALEX' }],
    }).length,
    1,
  );
  assert.equal(
    filterEvents(events, { filters: [{ field: 'IsInteractive', operator: 'neq', value: false }] })
      .length,
    1,
  );
  assert.equal(
    filterEvents(events, {
      filters: [
        {
          field: 'UserPrincipalName',
          operator: 'in',
          value: 'BOB@example.com, missing@example.com',
        },
      ],
    })[0].id,
    'b',
  );
});

test('local IPv4 and IPv6 CIDR evaluation agrees at network edges', () => {
  const events = normalizeEvents(
    ['192.0.2.0', '192.0.2.255', '192.0.3.0', '2001:db8::1', '2001:db9::1', '::ffff:192.0.2.1'].map(
      (ipAddress, i) => record({ id: String(i), ipAddress }),
    ),
  );
  assert.equal(filterEvents(events, { cidr: '192.0.2.0/24' }).length, 2);
  assert.equal(filterEvents(events, { cidr: '2001:db8::/32' }).length, 1);
  assert.equal(filterEvents(events, { cidr: '::ffff:192.0.2.0/120' }).length, 3);
  assert.equal(filterEvents(events, { cidr: '0.0.0.0/0' }).length, 3);
});

test('local absolute time range filters before limit and has no implicit today cutoff', () => {
  const events = normalizeEvents([
    record(),
    record({ id: 'b', createdDateTime: '2026-11-16T09:40:00Z' }),
  ]);
  assert.equal(filterEvents(events, {}).length, 2);
  assert.equal(
    filterEvents(events, {
      start: '2026-11-16T09:35:00Z',
      end: '2026-11-16T09:45:00Z',
      limit: 1,
    })[0].id,
    'b',
  );
});

test('spike query refuses a window without prior baseline time', () => {
  assert.throws(() => buildKql({ preset: 'spikes', hours: 1 }), /at least 2 hours/);
  assert.match(buildKql({ preset: 'spikes', hours: 24 }).query, /BaselineRecords >= 20/);
});

test('failure breakdowns group by code, IP and app with traceable event IDs', () => {
  const fail = (id, code, ip, app) =>
    record({ id, status: { errorCode: code }, ipAddress: ip, appDisplayName: app });
  const { breakdowns } = analyze(
    normalizeEvents([
      fail('1', 50126, '203.0.113.5', 'Office'),
      fail('2', 50126, '203.0.113.5', 'Teams'),
      fail('3', 53003, '', 'Office'),
      record({ id: '4' }),
    ]),
  );
  assert.deepEqual(breakdowns.errorCodes[0], { key: '50126', count: 2, eventIds: ['1', '2'] });
  assert.equal(breakdowns.ipAddresses.length, 1);
  assert.equal(breakdowns.applications[0].key, 'Office');
  assert.ok(!breakdowns.errorCodes.some((g) => g.eventIds.includes('4')));
});
