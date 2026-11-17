import test from 'node:test';
import assert from 'node:assert/strict';
import { AUTH_MODES, createCredential, getAuthStatus, SCOPES } from '../src/connectors/auth.js';
import { fetchGraphSignIns } from '../src/connectors/graph.js';
import { runLogAnalyticsQuery } from '../src/connectors/log-analytics.js';
import { requestJson } from '../src/connectors/http.js';

const credential = { getToken: async () => ({ token: 'private-test-token' }) };
const json = (value, status = 200, headers = {}) =>
  new Response(JSON.stringify(value), { status, headers });
const graphOptions = { start: '2026-11-15T00:00:00Z', end: '2026-11-16T00:00:00Z', credential };
const workspaceId = '11111111-2222-3333-4444-555555555555';

test('auth status never exports a client secret and distinguishes config from authentication', () => {
  const status = getAuthStatus({
    TRACEGLASS_AUTH_MODE: 'client-secret',
    TRACEGLASS_TENANT_ID: 'tenant',
    TRACEGLASS_CLIENT_ID: 'client',
    TRACEGLASS_CLIENT_SECRET: 'do-not-export',
  });
  assert.equal(status.configured, true);
  assert.equal(status.authenticated, false);
  assert.equal(JSON.stringify(status).includes('do-not-export'), false);
  assert.ok(AUTH_MODES.includes('managed-identity'));
});

test('explicit credentials do not fall back and device-code challenges use the supplied callback', async () => {
  let requested;
  class FakeCredential {
    constructor(...args) {
      requested = args;
    }
  }
  const identityModule = {
    DeviceCodeCredential: FakeCredential,
    ManagedIdentityCredential: FakeCredential,
    ClientSecretCredential: FakeCredential,
  };
  let challenge;
  await createCredential({
    env: {
      TRACEGLASS_AUTH_MODE: 'device-code',
      TRACEGLASS_TENANT_ID: 'tenant',
      TRACEGLASS_CLIENT_ID: 'client',
    },
    identityModule,
    onDeviceCode: (info) => {
      challenge = info;
    },
  });
  requested[0].userPromptCallback({
    userCode: 'DEMO-CODE',
    verificationUri: 'https://microsoft.com/devicelogin',
    message: 'Authenticate',
    expiresOn: new Date('2026-11-16T12:00:00Z'),
  });
  assert.equal(challenge.userCode, 'DEMO-CODE');
  assert.equal(challenge.expiresOn, '2026-11-16T12:00:00.000Z');
  await createCredential({
    env: { TRACEGLASS_AUTH_MODE: 'managed-identity', TRACEGLASS_CLIENT_ID: 'selected-identity' },
    identityModule,
  });
  assert.equal(requested[0].clientId, 'selected-identity');
  await assert.rejects(
    createCredential({ env: { TRACEGLASS_AUTH_MODE: 'client-secret' }, identityModule }),
    /TRACEGLASS_CLIENT_SECRET/,
  );
  await assert.rejects(createCredential({ env: { TRACEGLASS_AUTH_MODE: 'offline' } }), /Offline/);
});

test('Graph explicitly queries both event types, escapes users, paginates and deduplicates', async () => {
  const urls = [];
  const result = await fetchGraphSignIns({
    ...graphOptions,
    user: "o'neal@example.com",
    fetchImpl: async (url, options) => {
      urls.push(url);
      assert.equal(options.redirect, 'error');
      assert.equal(options.headers.Authorization, 'Bearer private-test-token');
      return urls.length === 1
        ? json({
            value: [{ id: 'one', appliedConditionalAccessPolicies: [] }],
            '@odata.nextLink': 'https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=two',
          })
        : json({
            value: [
              { id: 'one', appliedConditionalAccessPolicies: [] },
              { id: 'two', appliedConditionalAccessPolicies: [] },
            ],
          });
    },
  });
  const filter = new URL(urls[0]).searchParams.get('$filter');
  assert.match(filter, /interactiveUser/);
  assert.match(filter, /nonInteractiveUser/);
  assert.match(filter, /o''neal@example.com/);
  assert.equal(result.events.length, 2);
  assert.equal(result.metadata.pages, 2);
  assert.equal(result.metadata.complete, true);
});

test('Graph reports truncation and missing policy permissions', async () => {
  const result = await fetchGraphSignIns({
    ...graphOptions,
    maxEvents: 1,
    fetchImpl: async () =>
      json({
        value: [{ id: 'one' }],
        '@odata.nextLink': 'https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=two',
      }),
  });
  assert.equal(result.metadata.truncated, true);
  assert.equal(result.metadata.complete, false);
  assert.ok(
    result.warnings.some((warning) => warning.includes('appliedConditionalAccessPolicies')),
  );
});

test('Graph never sends authorization to an untrusted nextLink', async () => {
  let calls = 0;
  await assert.rejects(
    fetchGraphSignIns({
      ...graphOptions,
      fetchImpl: async () => {
        calls++;
        return json({
          value: [{ id: 'one' }],
          '@odata.nextLink': 'https://attacker.invalid/steal',
        });
      },
    }),
    (error) => error.code === 'UnsafeContinuation',
  );
  assert.equal(calls, 1);
});

test('Graph rejects different Graph resources and repeated continuation pages', async () => {
  await assert.rejects(
    fetchGraphSignIns({
      ...graphOptions,
      fetchImpl: async () =>
        json({ value: [], '@odata.nextLink': 'https://graph.microsoft.com/beta/users' }),
    }),
    /outside the sign-in/,
  );
  await assert.rejects(
    fetchGraphSignIns({
      ...graphOptions,
      fetchImpl: async () =>
        json({
          value: [],
          '@odata.nextLink': 'https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=repeat',
        }),
    }),
    /repeated/,
  );
});

test('Graph rejects unbounded windows before any requests', async () => {
  await assert.rejects(
    fetchGraphSignIns({
      ...graphOptions,
      start: '2020-01-01T00:00:00Z',
      fetchImpl: () => assert.fail('network must not run'),
    }),
    /31 days/,
  );
  await assert.rejects(fetchGraphSignIns({ ...graphOptions, apiVersion: 'v1.0' }), /beta/);
  await assert.rejects(
    fetchGraphSignIns({
      ...graphOptions,
      start: '2026-11-15T09:00:00',
      fetchImpl: () => assert.fail('network must not run'),
    }),
    /explicit timezone/,
  );
});

test('transport honors short retry delay, bounds retries, and hides remote errors and tokens', async () => {
  let calls = 0;
  const waits = [];
  const options = {
    url: new URL('https://graph.microsoft.com/beta/auditLogs/signIns'),
    credential,
    scope: SCOPES.graph,
  };
  const result = await requestJson({
    ...options,
    sleepImpl: async (ms) => waits.push(ms),
    fetchImpl: async () =>
      ++calls === 1 ? json({}, 429, { 'retry-after': '2' }) : json({ value: [] }),
  });
  assert.deepEqual(waits, [2000]);
  assert.deepEqual(result, { value: [] });
  await assert.rejects(
    requestJson({ ...options, fetchImpl: async () => json({ error: 'private-test-token' }, 403) }),
    (error) => !error.message.includes('private-test-token') && error.status === 403,
  );
  await assert.rejects(
    requestJson({ ...options, fetchImpl: async () => json({}, 429, { 'retry-after': '120' }) }),
    (error) => error.code === 'Throttled' && error.retryAfterSeconds === 120,
  );
});

test('Log Analytics projects typed rows and discloses successful HTTP partial errors', async () => {
  const result = await runLogAnalyticsQuery({
    workspaceId,
    query: 'SigninLogs | take 100',
    timespan: 'P1D',
    credential,
    fetchImpl: async (url, options) => {
      assert.equal(new URL(url).hostname, 'api.loganalytics.azure.com');
      assert.equal(options.method, 'POST');
      assert.equal(JSON.parse(options.body).timespan, 'P1D');
      return json({
        tables: [
          {
            name: 'PrimaryResult',
            columns: [
              { name: 'Id', type: 'string' },
              { name: 'IsInteractive', type: 'bool' },
            ],
            rows: [['one', false]],
          },
        ],
        error: { code: 'PartialError', message: 'Some tables unavailable' },
      });
    },
  });
  assert.deepEqual(result.events, [{ Id: 'one', IsInteractive: false }]);
  assert.equal(result.metadata.partial, true);
  assert.equal(result.metadata.complete, false);
});

test('Log Analytics flags a reached generated take limit as potentially incomplete', async () => {
  const result = await runLogAnalyticsQuery({
    workspaceId,
    query: 'SigninLogs | take 1',
    credential,
    fetchImpl: async () =>
      json({ tables: [{ name: 'PrimaryResult', columns: [{ name: 'Id' }], rows: [['one']] }] }),
  });
  assert.equal(result.metadata.limitReached, true);
  assert.equal(result.metadata.complete, false);
});

test('Log Analytics rejects malformed workspace, excessive windows and management commands', async () => {
  await assert.rejects(
    runLogAnalyticsQuery({ workspaceId: '../steal', query: 'SigninLogs', credential }),
    /UUID/,
  );
  await assert.rejects(
    runLogAnalyticsQuery({ workspaceId, query: 'SigninLogs', timespan: 'P1000D', credential }),
    /31 days/,
  );
  await assert.rejects(
    runLogAnalyticsQuery({ workspaceId, query: '.show tables', credential }),
    /management commands/,
  );
});
