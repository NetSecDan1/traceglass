/** Explicit credentials only: no ambient credential-chain fallback. */
export const AUTH_MODES = Object.freeze([
  'offline',
  'azure-cli',
  'interactive-browser',
  'device-code',
  'client-secret',
  'managed-identity',
]);
export const SCOPES = Object.freeze({
  graph: 'https://graph.microsoft.com/.default',
  logs: 'https://api.loganalytics.io/.default',
});

export function getAuthStatus(env = process.env) {
  const mode = env.TRACEGLASS_AUTH_MODE || 'azure-cli';
  const required = ['interactive-browser', 'device-code', 'client-secret'].includes(mode)
    ? ['TRACEGLASS_TENANT_ID', 'TRACEGLASS_CLIENT_ID']
    : [];
  if (mode === 'client-secret') required.push('TRACEGLASS_CLIENT_SECRET');
  const missing = required.filter((key) => !env[key]);
  return {
    mode,
    supportedModes: [...AUTH_MODES],
    configured: AUTH_MODES.includes(mode) && missing.length === 0,
    authenticated: false,
    authenticationState: 'not-checked',
    tenantId: env.TRACEGLASS_TENANT_ID || null,
    clientId: env.TRACEGLASS_CLIENT_ID || null,
    workspaceId: env.TRACEGLASS_WORKSPACE_ID || null,
    missing,
    requiresInteraction: ['interactive-browser', 'device-code'].includes(mode),
  };
}

export async function createCredential({ env = process.env, onDeviceCode, identityModule } = {}) {
  const status = getAuthStatus(env);
  if (!AUTH_MODES.includes(status.mode))
    throw new Error(`Unsupported authentication mode. Choose ${AUTH_MODES.join(', ')}.`);
  if (status.mode === 'offline')
    throw new Error(
      'Offline mode does not connect to Microsoft. Import an export or select an authentication mode.',
    );
  if (status.missing.length)
    throw new Error(`Authentication configuration is missing: ${status.missing.join(', ')}.`);
  const identity =
    identityModule ||
    (await import('@azure/identity').catch(() => {
      throw new Error(
        'Live authentication requires @azure/identity. Run npm install in the Traceglass project.',
      );
    }));
  const tenantId = env.TRACEGLASS_TENANT_ID || undefined;
  const clientId = env.TRACEGLASS_CLIENT_ID || undefined;
  switch (status.mode) {
    case 'azure-cli':
      return new identity.AzureCliCredential({ tenantId, processTimeoutInMs: 30000 });
    case 'interactive-browser':
      return new identity.InteractiveBrowserCredential({
        tenantId,
        clientId,
        redirectUri: 'http://localhost',
      });
    case 'device-code':
      if (typeof onDeviceCode !== 'function')
        throw new Error('Device-code authentication requires a prompt callback.');
      return new identity.DeviceCodeCredential({
        tenantId,
        clientId,
        userPromptCallback: (info) =>
          onDeviceCode({
            userCode: info.userCode,
            verificationUri: info.verificationUri,
            message: info.message,
            expiresOn:
              info.expiresOn instanceof Date ? info.expiresOn.toISOString() : info.expiresOn,
          }),
      });
    case 'client-secret':
      return new identity.ClientSecretCredential(tenantId, clientId, env.TRACEGLASS_CLIENT_SECRET);
    case 'managed-identity':
      return new identity.ManagedIdentityCredential(clientId ? { clientId } : {});
  }
}
