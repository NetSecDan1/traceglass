// Entirely synthetic, deterministic training records. No tenant data or real IP addresses.
import { writeFile } from 'node:fs/promises';
const events = [];
const policy = (id, displayName, result, controls = []) => ({
  id,
  displayName,
  result,
  enforcedGrantControls: controls,
  enforcedSessionControls: [],
});
const base = (number, time, user = 'alex.morgan', interactive = false) => ({
  id: `demo-event-${String(number).padStart(3, '0')}`,
  createdDateTime: `2026-11-16T${time}Z`,
  userPrincipalName: `${user}@example.com`,
  userDisplayName: user
    .split('.')
    .map((x) => x[0].toUpperCase() + x.slice(1))
    .join(' '),
  userId: `demo-user-${user}`,
  appId: 'demo-app-office',
  appDisplayName: 'Microsoft Office',
  resourceDisplayName: 'Microsoft Graph',
  ipAddress: '192.0.2.24',
  isInteractive: interactive,
  signInEventTypes: [interactive ? 'interactiveUser' : 'nonInteractiveUser'],
  status: { errorCode: 0, failureReason: '', additionalDetails: '' },
  conditionalAccessStatus: 'success',
  correlationId: `demo-correlation-${number}`,
  originalRequestId: `demo-request-${number}`,
  sessionId: `demo-session-${user}`,
  deviceDetail: {
    deviceId: 'demo-device-01',
    displayName: 'SYNTHETIC-WKS-01',
    operatingSystem: 'Windows 11',
    browser: interactive ? 'Edge 132' : '',
    isCompliant: true,
    isManaged: true,
    trustType: 'Azure AD joined',
  },
  location: { city: 'New York', countryOrRegion: 'US' },
  riskLevelDuringSignIn: 'none',
  riskState: 'none',
  clientAppUsed: interactive ? 'Browser' : 'Mobile Apps and Desktop clients',
  authenticationRequirement: 'multiFactorAuthentication',
  appliedConditionalAccessPolicies: [
    policy('demo-ca-01', 'Require phishing-resistant MFA', 'success', ['AuthenticationStrength']),
    policy('demo-ca-02', 'Require compliant device', 'success', ['CompliantDevice']),
  ],
  authenticationDetails: [
    {
      authenticationStepDateTime: `2026-11-16T${time}Z`,
      authenticationMethod: interactive ? 'FIDO2 security key' : 'Previously satisfied',
      succeeded: true,
      authenticationStepResultDetail: interactive
        ? 'MFA completed'
        : 'MFA requirement satisfied by claim in the token',
    },
  ],
});
for (let i = 0; i < 36; i++) {
  const minutes = 8 * 60 + i * 2;
  const event = base(
    i + 1,
    `${String(Math.floor(minutes / 60)).padStart(2, '0')}:${String(minutes % 60).padStart(2, '0')}:00`,
    ['alex.morgan', 'jamie.chen', 'sam.patel'][i % 3],
    i % 8 === 0,
  );
  if (i % 3) {
    event.ipAddress = i % 3 === 1 ? '198.51.100.12' : '203.0.113.8';
    event.appId = 'demo-app-teams';
    event.appDisplayName = 'Microsoft Teams';
    event.resourceDisplayName = 'Microsoft Teams Services';
  }
  events.push(event);
}
const signIn = base(37, '09:38:04', 'alex.morgan', true);
signIn.originalRequestId = signIn.id;
signIn.sessionId = 'demo-session-incident';
events.push(signIn);
for (let i = 0; i < 12; i++) {
  const event = base(
    38 + i,
    `09:${40 + Math.floor(i / 4)}:${String((i % 4) * 12).padStart(2, '0')}`,
  );
  event.status = {
    errorCode: 53000,
    failureReason: 'Device is not in required device state: compliant.',
    additionalDetails: 'Synthetic example: device compliance grant control failed.',
  };
  event.conditionalAccessStatus = 'failure';
  event.sessionId = 'demo-session-incident';
  event.originalRequestId = signIn.id;
  event.resourceDisplayName = i % 2 ? 'Office 365 Exchange Online' : 'Microsoft Graph';
  event.deviceDetail.isCompliant = false;
  event.appliedConditionalAccessPolicies = [
    policy('demo-ca-01', 'Require phishing-resistant MFA', 'success', ['AuthenticationStrength']),
    policy('demo-ca-02', 'Require compliant device', 'failure', ['CompliantDevice']),
    policy('demo-ca-03', 'Pilot: trusted networks', 'reportOnlyFailure', ['Block']),
  ];
  events.push(event);
}
const alternate = base(50, '09:44:05', 'alex.morgan', false);
alternate.status = {
  errorCode: 50126,
  failureReason: 'Invalid username or password.',
  additionalDetails: 'Synthetic authentication failure; CA not applied.',
};
alternate.conditionalAccessStatus = 'notApplied';
alternate.sessionId = '';
alternate.originalRequestId = '';
alternate.appliedConditionalAccessPolicies = [
  policy('demo-ca-02', 'Require compliant device', 'notApplied', ['CompliantDevice']),
];
events.push(alternate);
const report = base(51, '09:45:00', 'alex.morgan', true);
report.sessionId = 'demo-session-recovery';
report.appliedConditionalAccessPolicies.push(
  policy('demo-ca-03', 'Pilot: trusted networks', 'reportOnlyFailure', ['Block']),
);
events.push(report);
const missing = base(52, '09:46:20');
delete missing.appliedConditionalAccessPolicies;
missing.status = {
  errorCode: 53003,
  failureReason: 'Access blocked by Conditional Access policies.',
};
missing.conditionalAccessStatus = 'failure';
missing.sessionId = 'demo-session-incident';
events.push(missing);
const risk = base(53, '09:48:10', 'jamie.chen', true);
risk.ipAddress = '203.0.113.99';
risk.riskLevelDuringSignIn = 'high';
risk.riskState = 'atRisk';
risk.location = { city: 'London', countryOrRegion: 'GB' };
risk.appliedConditionalAccessPolicies.push(
  policy('demo-ca-04', 'Block high sign-in risk', 'failure', ['Block']),
);
risk.conditionalAccessStatus = 'failure';
risk.status = { errorCode: 53003, failureReason: 'Access blocked by Conditional Access policies.' };
events.push(risk);
const recovered = base(54, '09:52:18', 'alex.morgan', true);
recovered.sessionId = 'demo-session-new';
recovered.originalRequestId = recovered.id;
events.push(recovered);
for (let i = 0; i < 6; i++) {
  const event = base(
    55 + i,
    `10:${String(i * 4).padStart(2, '0')}:00`,
    i % 2 ? 'sam.patel' : 'alex.morgan',
    i % 3 === 0,
  );
  event.sessionId = i % 2 ? 'demo-session-sam' : 'demo-session-new';
  events.push(event);
}
await writeFile(
  new URL('./demo-signins.json', import.meta.url),
  JSON.stringify(
    {
      synthetic: true,
      description:
        'Synthetic Traceglass demonstration. All identities use example.com and all IP addresses are documentation ranges. No live tenant data.',
      value: events,
    },
    null,
    2,
  ) + '\n',
);
