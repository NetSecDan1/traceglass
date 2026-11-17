/** No response body, credential, request URL, or token is included in errors. */
export class ConnectorError extends Error {
  constructor(message, { code = 'ConnectorError', status = null, retryAfterSeconds = null } = {}) {
    super(message);
    this.name = 'ConnectorError';
    this.code = code;
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const trustedHosts = new Set(['graph.microsoft.com', 'api.loganalytics.azure.com']);

export function trustedUrl(value, expectedHost) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ConnectorError('Microsoft returned an invalid continuation URL.', {
      code: 'UnsafeContinuation',
    });
  }
  if (
    url.protocol !== 'https:' ||
    !trustedHosts.has(url.hostname) ||
    (expectedHost && url.hostname !== expectedHost) ||
    url.username ||
    url.password ||
    url.port
  ) {
    throw new ConnectorError('Refused an untrusted Microsoft API URL.', {
      code: 'UnsafeContinuation',
    });
  }
  return url;
}

function retryDelay(response, attempt) {
  const value = response.headers.get('retry-after');
  const numeric = value == null ? NaN : Number(value);
  const seconds = Number.isFinite(numeric) ? numeric : (Date.parse(value) - Date.now()) / 1000;
  return Math.max(0, Number.isFinite(seconds) ? seconds * 1000 : 1000 * 2 ** attempt);
}

export async function requestJson({
  url,
  credential,
  scope,
  method = 'GET',
  body,
  headers = {},
  fetchImpl = globalThis.fetch,
  sleepImpl = sleep,
  timeoutMs = 45000,
  maxRetries = 3,
}) {
  trustedUrl(url);
  if (!credential || typeof credential.getToken !== 'function')
    throw new ConnectorError('Select and configure authentication before connecting.', {
      code: 'AuthenticationRequired',
    });
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    let access;
    try {
      access = await credential.getToken(scope);
    } catch {
      throw new ConnectorError(
        'Microsoft authentication failed. Check the selected account, tenant, app configuration, consent, and your tenant authentication policy.',
        { code: 'AuthenticationFailed' },
      );
    }
    if (!access?.token)
      throw new ConnectorError('Microsoft did not return an access token.', {
        code: 'AuthenticationFailed',
      });
    let response;
    try {
      response = await fetchImpl(url.toString(), {
        method,
        headers: {
          Accept: 'application/json',
          ...headers,
          Authorization: `Bearer ${access.token}`,
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(timeoutMs),
        redirect: 'error',
      });
    } catch (error) {
      throw new ConnectorError(
        error?.name === 'TimeoutError' || error?.name === 'AbortError'
          ? 'Microsoft API request timed out. Narrow the time window and retry.'
          : 'Microsoft API request failed. Check network connectivity and the configured Microsoft cloud.',
        { code: 'TransportError' },
      );
    }
    if ([429, 502, 503, 504].includes(response.status) && attempt < maxRetries) {
      const waitMs = retryDelay(response, attempt);
      // Honor Retry-After rather than retrying prematurely; long waits return control to the analyst.
      if (waitMs > 10000)
        throw new ConnectorError(
          'Microsoft requested a longer retry delay. Wait before trying again.',
          {
            code: 'Throttled',
            status: response.status,
            retryAfterSeconds: Math.ceil(waitMs / 1000),
          },
        );
      await response.body?.cancel?.();
      await sleepImpl(waitMs);
      continue;
    }
    if (!response.ok) {
      const messages = {
        400: 'Microsoft rejected the request. Check query syntax, supported properties, and time bounds.',
        401: 'Microsoft rejected authentication. Sign in again with the intended tenant and account.',
        403: 'Microsoft denied access. Verify read permissions, admin consent, required roles, workspace access, and licensing.',
        404: 'The Microsoft resource was not found. Check the workspace ID and tenant.',
        429: 'Microsoft throttled the request. Narrow the time window or retry later.',
      };
      throw new ConnectorError(
        messages[response.status] ||
          'Microsoft could not complete the request. Retry with a smaller time window.',
        { code: 'MicrosoftApiError', status: response.status },
      );
    }
    try {
      return await response.json();
    } catch {
      throw new ConnectorError('Microsoft returned an invalid JSON response.', {
        code: 'InvalidResponse',
      });
    }
  }
}
