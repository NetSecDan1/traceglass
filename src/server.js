import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { createCredential, getAuthStatus, SCOPES } from './connectors/auth.js';
import { runLogAnalyticsQuery } from './connectors/log-analytics.js';
import { buildKql } from './core/kql.js';
import { loadDemo, loadDataset, investigate, collect } from './workspace.js';
import { evidenceBundle, markdownReport } from './report.js';

const assets = new Map([
  ['/', ['index.html', 'text/html']],
  ['/index.html', ['index.html', 'text/html']],
  ['/styles.css', ['styles.css', 'text/css']],
  ['/app.js', ['app.js', 'text/javascript']],
]);
const MAX_BODY = 20 * 1024 * 1024;
function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}
async function body(req) {
  if (!String(req.headers['content-type']).startsWith('application/json'))
    throw Object.assign(new Error('Use application/json.'), { status: 415 });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY)
      throw Object.assign(new Error('Import exceeds the 20 MB request limit.'), { status: 413 });
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  } catch {
    throw Object.assign(new Error('Invalid JSON.'), { status: 400 });
  }
}
export async function createServer({
  env = process.env,
  initialDataset,
  credentialFactory = createCredential,
  collectFn = collect,
} = {}) {
  let dataset = initialDataset || (await loadDemo());
  let credential;
  let credentialPromise;
  let auth = { status: 'idle' };
  let collecting = false;
  const csrfToken = randomBytes(32).toString('hex');
  const obtainCredential = async () => {
    if (credential) return credential;
    credentialPromise ||= Promise.resolve().then(() =>
      credentialFactory({
        env,
        onDeviceCode: (info) => {
          auth = {
            status: 'awaiting-user',
            challenge: {
              userCode: info.userCode,
              verificationUri: info.verificationUri,
              message: info.message,
              expiresOn: info.expiresOn,
            },
          };
        },
      }),
    );
    try {
      credential = await credentialPromise;
      return credential;
    } catch {
      credentialPromise = undefined;
      throw new Error(
        'Authentication configuration failed. Run doctor and review the configured credential, tenant, and app settings.',
      );
    }
  };
  const requestSucceeded = () => {
    auth = {
      status: 'authenticated',
      message: 'Microsoft read request succeeded. Permissions for other data sources may differ.',
    };
  };
  const requestFailed = () => {
    if (['authenticating', 'awaiting-user'].includes(auth.status))
      auth = {
        status: 'error',
        error:
          'Microsoft request did not complete. Review the request error and retry authentication if needed.',
      };
  };
  const server = http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );
    try {
      const port = server.address()?.port;
      const hosts = [`127.0.0.1:${port}`, `localhost:${port}`];
      if (!hosts.includes(req.headers.host))
        return json(res, 403, { error: 'Untrusted Host header.' });
      if (
        req.headers['sec-fetch-site'] === 'cross-site' ||
        (req.headers.origin && !hosts.some((h) => req.headers.origin === `http://${h}`))
      )
        return json(res, 403, { error: 'Cross-origin requests are not allowed.' });
      const url = new URL(req.url, `http://127.0.0.1:${port}`);
      if (!['GET', 'POST'].includes(req.method))
        return json(res, 405, { error: 'Method not allowed.' });
      if (req.method === 'POST' && req.headers['x-traceglass-csrf'] !== csrfToken)
        return json(res, 403, {
          error: 'Refresh this page to establish a valid workspace session.',
        });
      if (req.method === 'GET' && assets.has(url.pathname)) {
        const [file, type] = assets.get(url.pathname);
        res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8` });
        return res.end(await readFile(new URL(`../web/${file}`, import.meta.url)));
      }
      if (req.method === 'GET' && url.pathname === '/api/session')
        return json(res, 200, {
          csrfToken,
          config: {
            ...getAuthStatus(env),
            authMode: env.TRACEGLASS_AUTH_MODE || 'azure-cli',
            workspaceId: env.TRACEGLASS_WORKSPACE_ID || '',
          },
          source: dataset.metadata.source,
          demo: dataset.metadata.demo,
        });
      if (req.method === 'GET' && url.pathname === '/api/investigation')
        return json(res, 200, investigate(dataset, Object.fromEntries(url.searchParams)));
      if (req.method === 'GET' && url.pathname === '/api/auth/status') return json(res, 200, auth);
      if (req.method === 'GET' && url.pathname === '/api/export') {
        const result = investigate(dataset, Object.fromEntries(url.searchParams));
        const markdown = url.searchParams.get('format') === 'markdown';
        res.writeHead(200, {
          'Content-Type': markdown
            ? 'text/markdown; charset=utf-8'
            : 'application/json; charset=utf-8',
          'Content-Disposition': `attachment; filename="traceglass-evidence.${markdown ? 'md' : 'json'}"`,
        });
        return res.end(
          markdown ? markdownReport(result) : JSON.stringify(evidenceBundle(result), null, 2),
        );
      }
      if (req.method !== 'POST') return json(res, 404, { error: 'Not found.' });
      const input = await body(req);
      if (url.pathname === '/api/demo') {
        dataset = await loadDemo();
        return json(res, 200, investigate(dataset));
      }
      if (url.pathname === '/api/import') {
        dataset = await loadDataset(input.data);
        return json(res, 200, investigate(dataset));
      }
      if (url.pathname === '/api/query/build') return json(res, 200, buildKql(input.spec || {}));
      if (url.pathname === '/api/auth/login') {
        const source = input.source || 'graph';
        if (!['graph', 'log-analytics'].includes(source))
          return json(res, 400, { error: 'Select graph or log-analytics for authentication.' });
        if (auth.status === 'authenticating' || auth.status === 'awaiting-user')
          return json(res, 202, auth);
        auth = { status: 'authenticating' };
        // Only the authentication state is exposed. Tokens remain inside the credential implementation.
        (async () => {
          try {
            const c = await obtainCredential();
            await c.getToken(source === 'log-analytics' ? SCOPES.logs : SCOPES.graph);
            auth = {
              status: 'authenticated',
              message: `${source === 'log-analytics' ? 'Log Analytics' : 'Graph'} token acquired. API permissions are checked when a query runs.`,
            };
          } catch {
            auth = {
              status: 'error',
              error:
                'Authentication failed. Verify the configured credential, tenant, app consent, and access. SDK details are withheld to protect credentials.',
            };
          }
        })();
        return json(res, 202, auth);
      }
      if (url.pathname === '/api/collect') {
        if (!['graph', 'log-analytics'].includes(input.source))
          return json(res, 400, { error: 'Select graph or log-analytics for cloud collection.' });
        if (collecting) return json(res, 409, { error: 'A collection is already in progress.' });
        collecting = true;
        auth = { status: 'authenticating' };
        try {
          const next = await collectFn({
            source: input.source,
            user: input.user,
            start: input.start,
            end: input.end,
            maxEvents: 5000,
            workspaceId: input.workspaceId || env.TRACEGLASS_WORKSPACE_ID,
            credential: await obtainCredential(),
          });
          dataset = next;
          requestSucceeded();
          return json(res, 200, investigate(dataset));
        } catch (error) {
          requestFailed();
          throw error;
        } finally {
          collecting = false;
        }
      }
      if (url.pathname === '/api/query/run') {
        const spec = input.spec || {};
        const built = buildKql(spec);
        if (input.source !== 'log-analytics') {
          const core = await import('./core/kql.js');
          if (typeof core.filterEvents !== 'function')
            return json(res, 400, {
              error:
                'Local KQL execution is not available. Connect Log Analytics to run this query.',
              ...built,
            });
          const localEvents = core.filterEvents(dataset.events, spec);
          const limitReached = localEvents.length >= Number(spec.limit || 1000);
          return json(res, 200, {
            ...built,
            ...investigate({
              events: localEvents,
              metadata: {
                ...dataset.metadata,
                warnings: [
                  ...(dataset.metadata.warnings || []),
                  'Local preview filters the loaded evidence timeframe; the rolling hours setting applies only to live KQL. Aggregations execute only in Log Analytics.',
                  ...(limitReached
                    ? ['Local preview reached its result cap; matching evidence may be omitted.']
                    : []),
                ],
                queryPreview: true,
                complete: Boolean(dataset.metadata.complete) && !limitReached,
                truncated: Boolean(dataset.metadata.truncated) || limitReached,
              },
            }),
            tables: [],
          });
        }
        auth = { status: 'authenticating' };
        try {
          const result = await runLogAnalyticsQuery({
            workspaceId: input.workspaceId || env.TRACEGLASS_WORKSPACE_ID,
            query: built.query,
            timespan:
              spec.start && spec.end
                ? `${spec.start}/${spec.end}`
                : `PT${Number(spec.hours || 24)}H`,
            credential: await obtainCredential(),
          });
          requestSucceeded();
          return json(res, 200, {
            ...built,
            ...result,
            warnings: [...built.warnings, ...result.warnings],
          });
        } catch (error) {
          requestFailed();
          throw error;
        }
      }
      return json(res, 404, { error: 'Not found.' });
    } catch (error) {
      // Connector errors are sanitized at their boundary. Do not expose stacks or credentials.
      const known =
        error.code === 'ConnectorError' ||
        error.name === 'ConnectorError' ||
        error.status ||
        error.name === 'ValidationError' ||
        error instanceof TypeError ||
        error.constructor === Error;
      json(res, error.status && error.status >= 400 && error.status < 600 ? error.status : 400, {
        error: known ? error.message : 'Request failed. Check input and local configuration.',
      });
    }
  });
  server.requestTimeout = 120000;
  server.headersTimeout = 10000;
  return server;
}
export async function serve({
  port = Number(process.env.TRACEGLASS_PORT || 4318),
  ...options
} = {}) {
  if (!Number.isInteger(port) || port < 0 || port > 65535)
    throw new Error('Port must be between 0 and 65535.');
  const server = await createServer(options);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  console.log(
    `Traceglass is ready at http://127.0.0.1:${server.address().port}\nLocal workspace · synthetic demo loaded · Ctrl+C to stop`,
  );
  return server;
}
