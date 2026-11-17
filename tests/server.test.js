import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer } from '../src/server.js';
import { evidenceBundle, markdownReport } from '../src/report.js';
import { loadDataset, investigate, timeRange } from '../src/workspace.js';
const sample = [
  {
    id: 'event-1',
    createdDateTime: '2026-11-16T10:00:00Z',
    userPrincipalName: 'a@example.com',
    appDisplayName: '<script>alert(1)</script>',
    isInteractive: false,
    status: { errorCode: 53003 },
    conditionalAccessStatus: 'failure',
    appliedConditionalAccessPolicies: [
      { id: 'p1', displayName: 'Require device', result: 'failure' },
    ],
  },
];
async function fixture(t, options = {}) {
  const server = await createServer({
    initialDataset: await loadDataset(sample),
    env: { TRACEGLASS_AUTH_MODE: 'offline' },
    ...options,
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  );
  const base = `http://127.0.0.1:${server.address().port}`;
  const session = await (await fetch(base + '/api/session')).json();
  return { server, base, token: session.csrfToken };
}

function post(base, token, path, value = {}) {
  return fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Traceglass-CSRF': token },
    body: JSON.stringify(value),
  });
}
test('HTTP rejects cross-origin reads and tokenless mutations', async (t) => {
  const { base } = await fixture(t);
  assert.equal(
    (await fetch(base + '/api/session', { headers: { Origin: 'https://attacker.example' } }))
      .status,
    403,
  );
  assert.equal(
    (
      await fetch(base + '/api/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      })
    ).status,
    403,
  );
  const hostileHostStatus = await new Promise((resolve, reject) => {
    http
      .get(base + '/api/session', { headers: { Host: 'attacker.example' } }, (response) => {
        response.resume();
        resolve(response.statusCode);
      })
      .on('error', reject);
  });
  assert.equal(hostileHostStatus, 403);
});
test('scope and evidence exports preserve source and original records', async (t) => {
  const { base } = await fixture(t);
  const result = await (await fetch(base + '/api/investigation?user=a%40example.com')).json();
  assert.equal(result.events.length, 1);
  assert.equal(result.metadata.complete, false);
  const exportResult = await fetch(base + '/api/export?format=json');
  const bundle = await exportResult.json();
  assert.equal(bundle.investigation.events[0].raw.id, 'event-1');
  assert.match(bundle.integrity.digest, /^[a-f0-9]{64}$/);
  assert.match(exportResult.headers.get('content-disposition'), /attachment/);
});
test('authorized offline import replaces dataset and rejects invalid times', async (t) => {
  const { base, token } = await fixture(t);
  const response = await fetch(base + '/api/import', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Traceglass-CSRF': token },
    body: JSON.stringify({ data: { value: sample } }),
  });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).events.length, 1);
  assert.equal((await fetch(base + '/api/investigation?start=invalid')).status, 400);
});
test('query builder cannot execute raw KQL supplied by browser', async (t) => {
  const { base, token } = await fixture(t);
  const response = await fetch(base + '/api/query/build', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Traceglass-CSRF': token },
    body: JSON.stringify({ spec: { preset: 'ip', ip: '203.0.113.1" | union SecretTable' } }),
  });
  assert.equal(response.status, 400);
});
test('report preserves evidence references and has deterministic integrity digest', async () => {
  const result = investigate(await loadDataset(sample));
  assert.equal(evidenceBundle(result).integrity.digest, evidenceBundle(result).integrity.digest);
  assert.match(markdownReport(result), /event-1/);
  assert.ok(!markdownReport(result).includes('<script>'));
});
test('collection rejects reversed and unbounded time windows', () => {
  assert.throws(() => timeRange('2026-11-17', '2026-11-16'));
  assert.throws(() => timeRange('2025-01-01', '2026-01-01'));
  assert.throws(() => timeRange('bad', 'also bad'));
  assert.throws(() => timeRange('2026-11-16T09:00:00', '2026-11-16T10:00:00'));
});
test('export and reimport preserve contradictory raw observations', async () => {
  const source = await loadDataset([
    ...sample,
    { ...sample[0], status: { errorCode: 0 }, conditionalAccessStatus: 'success' },
  ]);
  const roundTrip = await loadDataset(evidenceBundle(investigate(source)));
  assert.equal(roundTrip.events[0].observationConflict, true);
  assert.equal(roundTrip.events[0].status.errorCode, null);
  assert.equal(roundTrip.events[0].observations.length, 2);
});

test('SDK authentication failures and configuration failures never expose credentials', async (t) => {
  const secret = 'sensitive-sdk-token-value';
  const { base, token } = await fixture(t, {
    credentialFactory: async () => ({
      getToken: async () => {
        throw Object.assign(new Error(secret), { code: 'SDK_AUTH_FAILURE' });
      },
    }),
  });
  await post(base, token, '/api/auth/login');
  const auth = await (await fetch(base + '/api/auth/status')).json();
  assert.equal(auth.status, 'error');
  assert.equal(JSON.stringify(auth).includes(secret), false);
  const broken = await fixture(t, {
    credentialFactory: async () => {
      throw new Error(secret);
    },
  });
  const response = await post(broken.base, broken.token, '/api/collect', { source: 'graph' });
  assert.equal(response.status, 400);
  assert.equal((await response.text()).includes(secret), false);
});

test('authentication uses the selected API audience without exposing its token', async (t) => {
  let scope;
  const { base, token } = await fixture(t, {
    credentialFactory: async () => ({
      getToken: async (requested) => {
        scope = requested;
        return { token: 'private-access-token' };
      },
    }),
  });
  await post(base, token, '/api/auth/login', { source: 'log-analytics' });
  const auth = await (await fetch(base + '/api/auth/status')).json();
  assert.equal(scope, 'https://api.loganalytics.io/.default');
  assert.equal(auth.status, 'authenticated');
  assert.equal(JSON.stringify(auth).includes('private-access-token'), false);
});

test('collection exposes a device challenge then clears it and preserves partial coverage', async (t) => {
  let completeAuthentication;
  let challengeStarted;
  const started = new Promise((resolve) => {
    challengeStarted = resolve;
  });
  const pending = new Promise((resolve) => {
    completeAuthentication = resolve;
  });
  t.after(() => completeAuthentication());
  const { base, token } = await fixture(t, {
    credentialFactory: async ({ onDeviceCode }) => ({
      getToken: async () => {
        onDeviceCode({
          userCode: 'DEMO-CODE',
          verificationUri: 'https://microsoft.com/devicelogin',
          message: 'Complete sign-in',
        });
        challengeStarted();
        await pending;
        return { token: 'private-access-token' };
      },
    }),
    collectFn: async ({ credential }) => {
      await credential.getToken();
      return loadDataset(sample, 'graph', {
        complete: false,
        truncated: true,
        warnings: ['Partial collection'],
      });
    },
  });
  const collection = post(base, token, '/api/collect', { source: 'graph' });
  await started;
  assert.equal(
    (await (await fetch(base + '/api/auth/status')).json()).challenge.userCode,
    'DEMO-CODE',
  );
  completeAuthentication();
  const result = await (await collection).json();
  assert.equal(result.metadata.complete, false);
  assert.equal(result.metadata.truncated, true);
  const auth = await (await fetch(base + '/api/auth/status')).json();
  assert.equal(auth.status, 'authenticated');
  assert.equal(auth.challenge, undefined);
});

test('capped local preview never claims complete evidence coverage', async (t) => {
  const { base, token } = await fixture(t, { initialDataset: await loadDataset(sample, 'demo') });
  const result = await (
    await post(base, token, '/api/query/run', { source: 'demo', spec: { limit: 1 } })
  ).json();
  assert.equal(result.metadata.truncated, true);
  assert.equal(result.metadata.complete, false);
  assert.ok(result.metadata.warnings.some((message) => message.includes('result cap')));
});
