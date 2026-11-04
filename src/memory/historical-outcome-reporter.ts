import {
  IncidentMemoryRecord,
  ResolutionVerificationStatus,
  ResolutionClassification,
  HistoricalOutcomeReport,
  HistoricalTransitionSummary
} from './types.js';

/**
 * Parses and extracts evidence metadata from an evidence text string and history entry.
 */
function parseEvidenceMetadata(evidence: string): {
  evidenceHash?: string | undefined;
  hasPassingTests: boolean;
  hasMergedPr: boolean;
  provenanceSource?: string | undefined;
  verificationType?: 'INDEPENDENTLY_VERIFIED' | 'USER_ASSERTION' | undefined;
  displayLabel?: string | undefined;
} {
  const hashMatch = evidence.match(/\[evidenceHash:\s*([a-f0-9]{64})\]/i);
  const evidenceHash = hashMatch ? hashMatch[1]!.toLowerCase() : undefined;

  const hasPassingTests =
    /\b\d+\s+passing tests\b/i.test(evidence) ||
    /tests\s+passed/i.test(evidence);

  const hasMergedPr =
    /merged in PR\s*#?\d+/i.test(evidence) ||
    /PR\s*#?\d+.*merged/i.test(evidence);

  let provenanceSource: string | undefined;
  if (/source:\s*(GITHUB_API|GIT_CLI|CI_CD_PIPELINE|OBSERVABILITY_SYSTEM|SWITCH_ROOM|USER_ASSERTION)/i.test(evidence)) {
    const match = evidence.match(/source:\s*(GITHUB_API|GIT_CLI|CI_CD_PIPELINE|OBSERVABILITY_SYSTEM|SWITCH_ROOM|USER_ASSERTION)/i);
    provenanceSource = match ? match[1] : undefined;
  }

  let verificationType: 'INDEPENDENTLY_VERIFIED' | 'USER_ASSERTION' | undefined;
  let displayLabel: string | undefined;

  if (/INDEPENDENTLY_VERIFIED/i.test(evidence)) {
    verificationType = 'INDEPENDENTLY_VERIFIED';
    displayLabel = 'Independently Verified';
  } else if (/USER_ASSERTION/i.test(evidence) || /USER_PROVIDED/i.test(evidence) || provenanceSource === 'USER_ASSERTION') {
    verificationType = 'USER_ASSERTION';
    displayLabel = 'USER_PROVIDED';
  }

  return {
    evidenceHash,
    hasPassingTests,
    hasMergedPr,
    provenanceSource,
    verificationType,
    displayLabel
  };
}

/**
 * Generates a comprehensive, audit-grade HistoricalOutcomeReport for an incident memory record.
 *
 * Safeguards Enforced:
 * 1. Current classification strictly reflects current resolution status, while hasHistoricalRegression
 *    preserves any prior regression occurrence across the entire lifecycle.
 * 2. Regressed incidents currently in REGRESSED are strictly flagged with REGRESSED_FIX_DO_NOT_REUSE
 *    and doNotReuseAsProvenFix: true.
 * 3. If a regressed incident later becomes VERIFIED_RESOLVED through fresh valid evidence, its classification
 *    reflects VERIFIED_RESOLVED while retaining its historical regression warning.
 * 4. Transitions are chronologically ordered (earliest to latest) with eventId tie-breaking.
 * 5. Preserves exact underlying provenance values: INDEPENDENTLY_VERIFIED and USER_ASSERTION.
 *    USER_PROVIDED may only be a display label, never a third verification type.
 * 6. Missing or unavailable evidence items are explicitly inventoried.
 */
export function generateHistoricalOutcomeReport(record: IncidentMemoryRecord): HistoricalOutcomeReport {
  const currentStatus: ResolutionVerificationStatus = record.verificationStatus ?? 'UNVERIFIED_PROPOSAL';
  const rawHistory = record.resolutionHistory ?? [];

  // Sort transitions strictly chronologically (ascending: earliest first) with event ID tie-breaker
  const sortedHistory = [...rawHistory].sort((a, b) => {
    const timeA = new Date(a.timestamp).getTime();
    const timeB = new Date(b.timestamp).getTime();
    if (timeA !== timeB) {
      return timeA - timeB;
    }
    return a.id.localeCompare(b.id);
  });

  // Track lifecycle flags across transitions
  let everRegressed = false;
  let hasIndependent = false;
  let hasUserAssertion = false;
  let hasPassingTests = false;
  let hasMergedPr = Boolean(record.prLink && record.prLink.length > 0);
  let hasObservability = false;
  let hasHumanConfirmation = false;

  const chronologicalTransitions: HistoricalTransitionSummary[] = sortedHistory.map((entry) => {
    if (entry.toStatus === 'REGRESSED') {
      everRegressed = true;
    }

    const meta = parseEvidenceMetadata(entry.evidence);
    if (meta.hasPassingTests) hasPassingTests = true;
    if (meta.hasMergedPr) hasMergedPr = true;

    if (entry.actor?.type === 'HUMAN') {
      hasHumanConfirmation = true;
    }

    let verificationType = meta.verificationType;
    let displayLabel = meta.displayLabel;

    if (!verificationType) {
      if (entry.actor?.type === 'SYSTEM' || entry.actor?.type === 'SENTINEL') {
        verificationType = 'INDEPENDENTLY_VERIFIED';
        displayLabel = 'Independently Verified';
      } else if (entry.actor?.type === 'HUMAN') {
        verificationType = 'USER_ASSERTION';
        displayLabel = 'USER_PROVIDED';
      }
    }

    if (verificationType === 'INDEPENDENTLY_VERIFIED') {
      hasIndependent = true;
    } else if (verificationType === 'USER_ASSERTION') {
      hasUserAssertion = true;
    }

    if (/observability/i.test(entry.evidence)) {
      hasObservability = true;
    }

    return {
      eventId: entry.id,
      fromStatus: entry.fromStatus,
      toStatus: entry.toStatus,
      timestamp: entry.timestamp,
      actor: entry.actor ? { ...entry.actor } : undefined,
      evidenceSummary: entry.evidence,
      evidenceHash: meta.evidenceHash,
      provenanceSource: meta.provenanceSource,
      verificationType,
      displayLabel
    };
  });

  const isCurrentRegressed = currentStatus === 'REGRESSED';
  const hasHistoricalRegression = everRegressed || isCurrentRegressed;

  // Determine overall verification type (preserving exact underlying values: INDEPENDENTLY_VERIFIED, USER_ASSERTION)
  let overallVerificationType: 'INDEPENDENTLY_VERIFIED' | 'USER_ASSERTION' | 'MIXED' | 'NONE' = 'NONE';
  let overallDisplayLabel: string | undefined;

  if (hasIndependent && hasUserAssertion) {
    overallVerificationType = 'MIXED';
    overallDisplayLabel = 'Mixed Verification';
  } else if (hasIndependent) {
    overallVerificationType = 'INDEPENDENTLY_VERIFIED';
    overallDisplayLabel = 'Independently Verified';
  } else if (hasUserAssertion) {
    overallVerificationType = 'USER_ASSERTION';
    overallDisplayLabel = 'USER_PROVIDED'; // Display label only
  }

  // Inventory missing or unavailable evidence
  const missingOrUnavailableEvidence: string[] = [];
  if (!hasMergedPr) {
    missingOrUnavailableEvidence.push('Merged PR reference');
  }
  if (!hasPassingTests) {
    missingOrUnavailableEvidence.push('Passing regression test run with consistent test counts');
  }
  if (!hasIndependent && !hasHumanConfirmation && !hasObservability) {
    missingOrUnavailableEvidence.push('Independent technical verification or maintainer confirmation');
  }
  if (currentStatus === 'UNVERIFIED_PROPOSAL') {
    missingOrUnavailableEvidence.push('Remediation verification bundle (PR merge, test pass, confirmation)');
  } else if (currentStatus === 'PARTIAL_RESOLUTION') {
    missingOrUnavailableEvidence.push('Complete resolution confirmation and defect closure proof');
  } else if (isCurrentRegressed) {
    missingOrUnavailableEvidence.push('Fresh resolution commit and passing regression test addressing the regression');
  }

  // 1. Classification reflects CURRENT resolution status
  const classification: ResolutionClassification = currentStatus as ResolutionClassification;

  // 2. Determine recommendation advisory and proven fix eligibility
  let recommendationAdvisory:
    | 'PROVEN_FIX_AVAILABLE'
    | 'PARTIAL_MITIGATION_ONLY'
    | 'REGRESSED_FIX_DO_NOT_REUSE'
    | 'UNVERIFIED_PROPOSAL_ONLY';
  let doNotReuseAsProvenFix: boolean;

  if (isCurrentRegressed) {
    // Currently regressed: strictly block reuse as proven fix
    recommendationAdvisory = 'REGRESSED_FIX_DO_NOT_REUSE';
    doNotReuseAsProvenFix = true;
  } else if (currentStatus === 'VERIFIED_RESOLVED') {
    recommendationAdvisory = 'PROVEN_FIX_AVAILABLE';
    doNotReuseAsProvenFix = false;
  } else if (currentStatus === 'PARTIAL_RESOLUTION') {
    recommendationAdvisory = 'PARTIAL_MITIGATION_ONLY';
    doNotReuseAsProvenFix = false;
  } else {
    recommendationAdvisory = 'UNVERIFIED_PROPOSAL_ONLY';
    doNotReuseAsProvenFix = false;
  }

  return {
    incidentId: record.id,
    canonicalRepository: record.canonicalRepository,
    currentStatus,
    classification,
    isRegressed: isCurrentRegressed,
    hasHistoricalRegression,
    doNotReuseAsProvenFix,
    recommendationAdvisory,
    rootCause: record.rootCause,
    fixSummary: record.fixSummary,
    prLink: record.prLink,
    evidenceProvenanceSummary: {
      verificationType: overallVerificationType,
      displayLabel: overallDisplayLabel,
      hasPassingRegressionTests: hasPassingTests,
      hasMergedPrEvidence: hasMergedPr,
      hasObservabilityProof: hasObservability,
      hasHumanConfirmation,
      missingOrUnavailableEvidence
    },
    chronologicalTransitions,
    rawHistoryCount: rawHistory.length
  };
}

/**
 * Formats a historical outcome report into clean, safe Markdown for presentation in reports or chat.
 */
export function formatOutcomeReportMarkdown(report: HistoricalOutcomeReport): string {
  const lines: string[] = [];

  lines.push(`### Historical Outcome: \`${report.incidentId}\` [${report.currentStatus}]`);
  lines.push(`- **Repository:** \`${report.canonicalRepository}\``);
  lines.push(`- **Advisory:** \`${report.recommendationAdvisory}\``);

  if (report.doNotReuseAsProvenFix) {
    lines.push(
      `> ⚠️ **CRITICAL WARNING:** This incident is currently in a **REGRESSED** state. Do NOT recommend this remediation as a proven fix.`
    );
  } else if (report.hasHistoricalRegression) {
    lines.push(
      `> ⚠️ **HISTORICAL REGRESSION WARNING:** This incident experienced a prior regression in its lifecycle before resolution was verified with fresh evidence.`
    );
  }

  lines.push(`- **Root Cause:** ${report.rootCause}`);
  lines.push(`- **Fix Summary:** ${report.fixSummary}`);
  lines.push(`- **PR Reference:** ${report.prLink}`);
  lines.push(
    `- **Provenance Type:** \`${report.evidenceProvenanceSummary.verificationType}\`${
      report.evidenceProvenanceSummary.displayLabel
        ? ` (${report.evidenceProvenanceSummary.displayLabel})`
        : ''
    }`
  );

  if (report.evidenceProvenanceSummary.hasHumanConfirmation && !report.evidenceProvenanceSummary.hasPassingRegressionTests) {
    lines.push(`> *Note: Resolution contains human operator assertion without independent automated regression test verification.*`);
  }

  if (report.evidenceProvenanceSummary.missingOrUnavailableEvidence.length > 0) {
    lines.push('- **Missing or Unavailable Evidence:**');
    for (const item of report.evidenceProvenanceSummary.missingOrUnavailableEvidence) {
      lines.push(`  - ${item}`);
    }
  }

  if (report.chronologicalTransitions.length > 0) {
    lines.push('- **Lifecycle Transition History:**');
    for (const t of report.chronologicalTransitions) {
      const fromStr = t.fromStatus ? `${t.fromStatus} ➔ ` : '';
      const actorStr = t.actor ? ` by ${t.actor.name} (${t.actor.type})` : '';
      lines.push(`  - \`${t.timestamp}\` [${t.eventId}]: ${fromStr}\`${t.toStatus}\`${actorStr} — ${t.evidenceSummary}`);
    }
  } else {
    lines.push('- **Lifecycle Transition History:** *(No recorded transitions)*');
  }

  return lines.join('\n');
}
