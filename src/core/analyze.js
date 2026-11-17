const isFailure = (event) => event.status.errorCode !== null && event.status.errorCode !== 0;
const isCaFailure = (event) =>
  event.conditionalAccessStatus === 'failure' ||
  event.policies.some((policy) => policy.result === 'failure');
const sameIdentity = (a, b) =>
  a.userId && b.userId
    ? a.userId === b.userId
    : Boolean(
        a.userPrincipalName &&
          b.userPrincipalName &&
          a.userPrincipalName.toLowerCase() === b.userPrincipalName.toLowerCase(),
      );

/** Analyze observed evidence. Shared identifiers establish an association, not causality. */
export function analyze(events) {
  if (!Array.isArray(events)) throw new TypeError('analyze expects normalized events.');
  const summary = {
    total: events.length,
    interactive: events.filter((e) => e.isInteractive === true).length,
    nonInteractive: events.filter((e) => e.isInteractive === false).length,
    successes: events.filter((e) => e.status.errorCode === 0).length,
    failures: events.filter(isFailure).length,
    caFailures: events.filter(isCaFailure).length,
    reportOnlyFailures: events.filter((e) =>
      e.policies.some((p) => p.result === 'reportOnlyFailure'),
    ).length,
    unknown: events.filter((e) => e.status.errorCode === null).length,
  };
  const findings = [],
    links = [],
    policies = new Map();
  const finding = (id, severity, title, detail, items) => {
    if (items.length)
      findings.push({ id, severity, title, detail, eventIds: items.map((e) => e.id) });
  };
  const blocked = events.filter((e) => isCaFailure(e) && isFailure(e));
  finding(
    'ca-enforced',
    'critical',
    'Conditional Access enforcement observed',
    `${blocked.length} failed sign-in${blocked.length === 1 ? '' : 's'} also recorded an enforced Conditional Access failure. Review the per-policy grant controls. This establishes observed enforcement, not whether the configuration matched business intent.`,
    blocked,
  );
  const unexplainedCa = events.filter((e) => isCaFailure(e) && !isFailure(e));
  finding(
    'ca-outcome-conflict',
    'warning',
    'Conditional Access and sign-in results need review',
    'A Conditional Access failure appears with a successful or unknown sign-in result. Inspect the raw record and source completeness before attributing a block.',
    unexplainedCa,
  );
  const nonCa = events.filter(
    (e) =>
      isFailure(e) &&
      !isCaFailure(e) &&
      ['success', 'notApplied'].includes(e.conditionalAccessStatus),
  );
  finding(
    'other-failures',
    'info',
    'Other sign-in failures are present',
    `${nonCa.length} failed sign-in${nonCa.length === 1 ? '' : 's'} recorded Conditional Access success or not applied. Use the error code and authentication details to investigate these separately.`,
    nonCa,
  );
  const reportOnly = events.filter((e) => e.policies.some((p) => p.result === 'reportOnlyFailure'));
  finding(
    'report-only',
    'info',
    'Report-only results do not block access',
    'Report-only failure describes a simulated policy outcome. It is not evidence that this policy denied the sign-in; another enforced policy may still have failed.',
    reportOnly,
  );
  const missing = events.filter((e) => e.policyVisibility === 'missing');
  finding(
    'missing-policies',
    'warning',
    'Policy-level evidence is incomplete',
    `${missing.length} record${missing.length === 1 ? '' : 's'} omitted readable policy details. Permissions, export format, or collection coverage may explain the gap. Missing details must not be interpreted as no policies applied.`,
    missing,
  );
  finding(
    'conflicting-observations',
    'warning',
    'Conflicting event observations were preserved',
    'The same event appears with contradictory results across observations. Its outcome remains unknown, and the original revisions are retained in the evidence export under observations. Verify collection timestamps and source updates before making an attribution.',
    events.filter((e) => e.observationConflict),
  );
  const unknownTypes = events.filter((e) => e.isInteractive === null);
  finding(
    'unknown-types',
    'warning',
    'Some sign-in types are unknown',
    'These records did not identify whether authentication was interactive. They are excluded from interactive versus non-interactive comparisons.',
    unknownTypes,
  );
  const invalidTimes = events.filter((e) => !e.timestamp);
  finding(
    'invalid-time',
    'warning',
    'Some records have no valid timestamp',
    'Records without a valid event timestamp remain in counts but cannot support time-based links or spike detection.',
    invalidTimes,
  );

  const ordered = events
    .filter((e) => e.timestamp)
    .slice()
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  // Index the most recent matching identifier rather than implying that every event in a session is a direct token exchange.
  const identifiers = new Map(),
    recent = new Map();
  const divergence = [];
  for (const event of ordered) {
    const identity = event.userId || event.userPrincipalName.toLowerCase();
    let linked;
    if (identity) {
      for (const field of ['originalRequestId', 'correlationId', 'sessionId']) {
        const value = event[field];
        if (!value) continue;
        const key = `${identity}|${field}|${value}`;
        const prior = identifiers.get(key);
        if (prior && prior.id !== event.id && sameIdentity(prior, event)) {
          linked = {
            from: prior.id,
            to: event.id,
            strength: 'strong',
            reason: `Shared ${field}; association only, not proof of token lineage`,
            deltaSeconds: (Date.parse(event.timestamp) - Date.parse(prior.timestamp)) / 1000,
          };
          break;
        }
      }
      if (!linked && event.originalRequestId) {
        const prior = identifiers.get(`${identity}|id|${event.originalRequestId}`);
        if (prior && prior.id !== event.id && sameIdentity(prior, event))
          linked = {
            from: prior.id,
            to: event.id,
            strength: 'strong',
            reason: 'Original request matches an earlier event ID; association only',
            deltaSeconds: (Date.parse(event.timestamp) - Date.parse(prior.timestamp)) / 1000,
          };
      }
      const app =
        event.appId ||
        (event.appDisplayName && event.appDisplayName !== 'Unknown application'
          ? event.appDisplayName
          : '');
      const recentKey = `${identity}|${app}`;
      const previousInteractive = app ? recent.get(recentKey) : undefined;
      const delta = previousInteractive
        ? (Date.parse(event.timestamp) - Date.parse(previousInteractive.timestamp)) / 1000
        : Infinity;
      if (
        event.isInteractive === false &&
        previousInteractive &&
        delta >= 0 &&
        delta <= 1800 &&
        sameIdentity(previousInteractive, event)
      ) {
        if (!linked)
          linked = {
            from: previousInteractive.id,
            to: event.id,
            strength: 'context',
            reason:
              'Same user and application within 30 minutes; temporal context, session relationship unproven',
            deltaSeconds: delta,
          };
        if (previousInteractive.status.errorCode === 0 && isFailure(event)) divergence.push(event);
      }
      if (app && event.isInteractive === true) recent.set(recentKey, event);
      for (const field of ['originalRequestId', 'correlationId', 'sessionId', 'id'])
        if (event[field]) identifiers.set(`${identity}|${field}|${event[field]}`, event);
    }
    if (linked) links.push(linked);
  }
  finding(
    'interactive-divergence',
    'warning',
    'Interactive success, background failure',
    `${divergence.length} non-interactive failure${divergence.length === 1 ? '' : 's'} followed a successful interactive sign-in for the same user and app within 30 minutes. Compare resource, device, IP, authentication details, and policy results. Proximity alone does not establish a shared session or root cause.`,
    divergence,
  );

  for (const event of events)
    for (const policy of event.policies) {
      const key = policy.id || `name:${policy.displayName}`;
      if (!policies.has(key))
        policies.set(key, {
          id: policy.id,
          displayName: policy.displayName,
          success: 0,
          failure: 0,
          reportOnlyFailure: 0,
          notApplied: 0,
          other: 0,
          total: 0,
        });
      const aggregate = policies.get(key);
      aggregate.total++;
      if (['success', 'failure', 'reportOnlyFailure', 'notApplied'].includes(policy.result))
        aggregate[policy.result]++;
      else aggregate.other++;
    }
  const spikes = detectSpikes(ordered);
  if (spikes.candidates.length)
    findings.push({
      id: 'ca-spike',
      severity: 'warning',
      title: 'Conditional Access failure concentration',
      detail: `${spikes.candidates.length} five-minute interval${spikes.candidates.length === 1 ? '' : 's'} exceeded the preceding sample's failure rate and volume thresholds. This is a sample-relative triage signal, not a tenant-wide anomaly verdict.`,
      eventIds: ordered
        .filter(
          (e) =>
            isCaFailure(e) &&
            spikes.candidates.some(
              (c) =>
                Date.parse(e.timestamp) >= Date.parse(c.timestamp) &&
                Date.parse(e.timestamp) < Date.parse(c.timestamp) + 300000,
            ),
        )
        .map((e) => e.id),
    });
  const caveats = [
    'Observed enforcement does not prove that a policy was configured correctly or matched business intent. Compare the event-time policy configuration, exclusions, and approved requirements.',
    'Shared correlation, original-request, or session identifiers associate records; nearby timestamps alone do not prove token lineage.',
    'Findings describe only the supplied records. Retention, ingestion delays, sampling, source permissions, and query limits can leave gaps.',
    'For some confidential-client non-interactive sign-ins, the logged IP can reflect original token issuance rather than the current request origin. Portal exports may group similar events.',
  ];
  return {
    summary,
    findings,
    links,
    policies: [...policies.values()].sort((a, b) => b.failure - a.failure || b.total - a.total),
    spikes,
    coverage: {
      policyDetailsAvailable: events.length - missing.length,
      policyDetailsMissing: missing.length,
      invalidTimestamps: invalidTimes.length,
    },
    caveats,
  };
}

function detectSpikes(events) {
  const byBucket = new Map();
  for (const event of events) {
    const timestamp = new Date(
      Math.floor(Date.parse(event.timestamp) / 300000) * 300000,
    ).toISOString();
    if (!byBucket.has(timestamp))
      byBucket.set(timestamp, { timestamp, total: 0, caFailures: 0, rate: 0 });
    const bucket = byBucket.get(timestamp);
    bucket.total++;
    if (isCaFailure(event)) bucket.caFailures++;
  }
  const bins = [...byBucket.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  const candidates = [];
  let priorTotal = 0,
    priorFailures = 0;
  for (const bin of bins) {
    bin.rate = bin.caFailures / bin.total;
    bin.baselineRate = priorTotal ? priorFailures / priorTotal : null;
    bin.thresholdRate = bin.baselineRate === null ? null : Math.max(0.2, bin.baselineRate * 3);
    if (priorTotal >= 20 && bin.total >= 5 && bin.caFailures >= 3 && bin.rate > bin.thresholdRate)
      candidates.push({ ...bin });
    priorTotal += bin.total;
    priorFailures += bin.caFailures;
  }
  return {
    bins,
    baselineRate: priorTotal ? priorFailures / priorTotal : null,
    thresholdRate: null,
    candidates,
    caveat:
      'Five-minute observed-event buckets; compare at least 20 preceding records, minimum 5 current records and 3 CA failures, rate above 3× baseline and 20%. Sparse or partial samples are not tenant baselines. Empty buckets are not evidence of successful operation.',
  };
}
