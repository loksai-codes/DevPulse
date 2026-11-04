import { randomBytes } from 'node:crypto';
import {
  IncidentMemoryRecord,
  ResolutionVerificationStatus,
  ResolutionHistoryEntry,
  normalizeCanonicalRepository
} from './types.js';
import {
  FullResolutionVerificationBundle,
  FullResolutionVerificationBundleSchema,
  PartialResolutionEvidence,
  PartialResolutionEvidenceSchema,
  RegressionEvidence,
  RegressionEvidenceSchema,
  UnverifiedProposalEvidence,
  UnverifiedProposalEvidenceSchema,
  isRegressionTestExecutionSuccessful,
  computeEvidenceHash
} from './resolution-evidence.js';

/**
 * Strict state transition matrix.
 * Enforces allowed paths between resolution verification states.
 */
export const ALLOWED_TRANSITIONS: Record<
  ResolutionVerificationStatus,
  ReadonlySet<ResolutionVerificationStatus>
> = {
  UNVERIFIED_PROPOSAL: new Set(['PARTIAL_RESOLUTION', 'VERIFIED_RESOLVED', 'REGRESSED']),
  PARTIAL_RESOLUTION: new Set(['VERIFIED_RESOLVED', 'REGRESSED']),
  VERIFIED_RESOLVED: new Set(['REGRESSED']),
  REGRESSED: new Set(['UNVERIFIED_PROPOSAL', 'VERIFIED_RESOLVED'])
};

export interface VerificationOptions {
  maxEvidenceAgeMs?: number; // Maximum age of evidence timestamps (default: 30 days)
  now?: Date;                 // Reference timestamp for temporal checks
}

export interface StateTransitionResult {
  valid: boolean;
  fromStatus?: ResolutionVerificationStatus | undefined;
  toStatus: ResolutionVerificationStatus;
  reasons: string[];
  missingEvidence: string[];
  evidenceHash?: string | undefined;
  proposedHistoryEntry?: ResolutionHistoryEntry | undefined;
}

const DEFAULT_MAX_EVIDENCE_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

/**
 * ResolutionVerifier Engine.
 *
 * Implements strict, evidence-grounded verification gates for incident resolution lifecycles:
 * - Enforces allowed state transitions.
 * - Requires complete proof across all four pillars (PR, Diff Integrity, Regression Tests, Recovery Confirmation)
 *   before permitting VERIFIED_RESOLVED.
 * - Rejects expired, duplicate, inconsistent, or user-asserted claims masquerading as independent proof.
 * - Preserves transition history details in structured result objects.
 */
export class ResolutionVerifier {
  /**
   * Verifies all evidence for a VERIFIED_RESOLVED transition.
   * Requires proof across all 4 pillars:
   * 1. Merged PR evidence (commit SHA, base branch, merge timestamp)
   * 2. Diff integrity (proposed diff vs actual merged diff, with reconciliation if different)
   * 3. Regression test evidence (zero failures, >0 passed tests, count consistency)
   * 4. Resolution confirmation (observability recovery proof or verified human confirmation)
   */
  public static verifyFullResolution(
    record: IncidentMemoryRecord,
    bundleRaw: unknown,
    options: VerificationOptions = {}
  ): StateTransitionResult {
    const fromStatus = record.verificationStatus;
    const toStatus: ResolutionVerificationStatus = 'VERIFIED_RESOLVED';
    const reasons: string[] = [];
    const missingEvidence: string[] = [];

    // 1. Validate State Transition Path
    const transitionCheck = this.checkTransitionAllowed(fromStatus, toStatus);
    if (!transitionCheck.valid) {
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons: [transitionCheck.reason!],
        missingEvidence: ['Allowed state transition path']
      };
    }

    // 2. Validate Schema Bundle
    const parsedBundle = FullResolutionVerificationBundleSchema.safeParse(bundleRaw);
    if (!parsedBundle.success) {
      const fieldErrors = parsedBundle.error.errors.map(
        (e) => `${e.path.join('.')}: ${e.message}`
      );
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons: ['Evidence bundle failed schema validation', ...fieldErrors],
        missingEvidence: fieldErrors
      };
    }

    const bundle: FullResolutionVerificationBundle = parsedBundle.data;

    // 3. Incident ID and Canonical Repository Isolation
    if (bundle.incidentId !== record.id) {
      reasons.push(
        `Incident ID mismatch: evidence is for '${bundle.incidentId}', but record is '${record.id}'`
      );
    }

    let recordRepo: string;
    let evidenceRepo: string;
    try {
      recordRepo = normalizeCanonicalRepository(record.canonicalRepository);
      evidenceRepo = normalizeCanonicalRepository(bundle.canonicalRepository);
      if (recordRepo !== evidenceRepo) {
        reasons.push(
          `Repository isolation violation: evidence is for '${evidenceRepo}', record belongs to '${recordRepo}'`
        );
      }
    } catch (repoErr) {
      reasons.push(`Repository normalization failed: ${String(repoErr)}`);
    }

    // 4. Diff Integrity Verification
    // A proposed diff hash must match the incident record's diffHash
    if (bundle.diff.proposedDiffHash.toLowerCase() !== record.diffHash.toLowerCase()) {
      reasons.push(
        `Proposed diffHash mismatch: evidence references proposed diff '${bundle.diff.proposedDiffHash}', but record expects '${record.diffHash}'`
      );
    }

    // If actual merged diff differs from proposed diff, verify explicit reconciliation
    const diffsIdentical =
      bundle.diff.proposedDiffHash.toLowerCase() === bundle.diff.actualMergedDiffHash.toLowerCase();
    if (!diffsIdentical) {
      if (!bundle.diff.isReconciled) {
        reasons.push(
          'Merged diff hash differs from proposed diff hash and is not marked as reconciled (isReconciled=false)'
        );
      } else {
        reasons.push(
          `Merged diff hash was reconciled by ${bundle.diff.reconciledBy?.name ?? 'unknown'}: ${bundle.diff.reconciliationReason}`
        );
      }
    }

    // 5. Regression Test Execution Verification
    if (!isRegressionTestExecutionSuccessful(bundle.regressionTests)) {
      reasons.push(
        `Regression tests did not demonstrate passing execution (failed: ${bundle.regressionTests.failedTests}, passed: ${bundle.regressionTests.passedTests}, total: ${bundle.regressionTests.totalTests})`
      );
      missingEvidence.push('Passing regression test run with zero failures and at least one passed test');
    }

    // 6. Resolution Recovery Confirmation
    if (bundle.confirmation.provenance.verificationType === 'INDEPENDENTLY_VERIFIED') {
      if (!bundle.confirmation.observabilityEvidence) {
        reasons.push('Independent verification requires automated observability evidence');
        missingEvidence.push('Observability recovery evidence (metric or log proof)');
      }
    }

    // 7. Temporal Checks (Freshness, Expiration, No Future Timestamps)
    const now = options.now ?? new Date();
    const maxAgeMs = options.maxEvidenceAgeMs ?? DEFAULT_MAX_EVIDENCE_AGE_MS;

    const timestamps = [
      { label: 'PR Merged', ts: bundle.pr.mergedAt },
      { label: 'Regression Tests Executed', ts: bundle.regressionTests.executedAt },
      { label: 'Resolution Confirmed', ts: bundle.confirmation.confirmedAt }
    ];

    for (const item of timestamps) {
      const freshness = this.checkTimestampFreshness(item.ts, now, maxAgeMs);
      if (!freshness.valid) {
        reasons.push(`${item.label} timestamp error: ${freshness.reason}`);
        missingEvidence.push(`Valid, unexpired ${item.label} evidence`);
      }
    }

    // 8. Provenance Safeguards: Never accept USER_ASSERTION claiming INDEPENDENTLY_VERIFIED
    if (
      bundle.pr.provenance.source === 'USER_ASSERTION' &&
      bundle.pr.provenance.verificationType === 'INDEPENDENTLY_VERIFIED'
    ) {
      reasons.push("PR evidence from 'USER_ASSERTION' cannot claim independent verification");
    }

    // 9. Replay & Duplicate Evidence Protection
    const evidenceHash = computeEvidenceHash(bundle);
    if (this.isEvidenceReplayed(record, evidenceHash)) {
      reasons.push(`Duplicate evidence detected: exact evidence payload hash '${evidenceHash}' was previously recorded`);
      missingEvidence.push('Fresh, non-replayed resolution evidence');
    }

    // 10. Freshness Requirement for Regressed Recovery
    if (fromStatus === 'REGRESSED') {
      // Must not reuse the commit SHA or diff that caused the regression
      const replayedCommit = record.resolutionHistory.some((h) =>
        h.evidence.includes(bundle.pr.mergeCommitSha.slice(0, 7))
      );
      if (replayedCommit) {
        reasons.push(
          `Regressed incident recovery cannot reuse merge commit '${bundle.pr.mergeCommitSha.slice(0, 7)}' that previously failed`
        );
        missingEvidence.push('Fresh commit SHA addressing the regression');
      }
    }

    const isValid = reasons.length === 0 || reasons.every((r) => r.startsWith('Merged diff hash was reconciled'));
    if (!isValid) {
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons,
        missingEvidence,
        evidenceHash
      };
    }

    // Construct proposed history entry
    const actor =
      bundle.confirmation.humanConfirmation?.actor ??
      bundle.pr.provenance.capturedBy ?? {
        type: 'SYSTEM',
        id: 'resolution_verifier',
        name: 'Automated Resolution Verifier'
      };

    const proposedHistoryEntry: ResolutionHistoryEntry = {
      id: `rh_${Date.now()}_${randomBytes(3).toString('hex')}`,
      fromStatus,
      toStatus,
      timestamp: now.toISOString(),
      evidence: `Verified resolution merged in PR #${bundle.pr.prNumber} (${bundle.pr.mergeCommitSha.slice(0, 7)}) with ${bundle.regressionTests.passedTests} passing tests. [evidenceHash: ${evidenceHash}]`,
      actor
    };

    return {
      valid: true,
      fromStatus,
      toStatus,
      reasons: [
        `PR #${bundle.pr.prNumber} merged into ${bundle.pr.baseBranch}`,
        `Regression tests verified: ${bundle.regressionTests.passedTests}/${bundle.regressionTests.totalTests} passed`,
        `Resolution confirmed with valid recovery proof`,
        `Evidence fingerprint: ${evidenceHash}`
      ],
      missingEvidence: [],
      evidenceHash,
      proposedHistoryEntry
    };
  }

  /**
   * Verifies partial mitigation evidence.
   */
  public static verifyPartialResolution(
    record: IncidentMemoryRecord,
    evidenceRaw: unknown,
    options: VerificationOptions = {}
  ): StateTransitionResult {
    const fromStatus = record.verificationStatus;
    const toStatus: ResolutionVerificationStatus = 'PARTIAL_RESOLUTION';
    const reasons: string[] = [];
    const missingEvidence: string[] = [];

    // 1. Transition check
    const transitionCheck = this.checkTransitionAllowed(fromStatus, toStatus);
    if (!transitionCheck.valid) {
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons: [transitionCheck.reason!],
        missingEvidence: ['Allowed state transition path']
      };
    }

    // 2. Schema check
    const parsed = PartialResolutionEvidenceSchema.safeParse(evidenceRaw);
    if (!parsed.success) {
      const fieldErrors = parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`);
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons: ['Partial resolution evidence failed schema validation', ...fieldErrors],
        missingEvidence: fieldErrors
      };
    }

    const evidence: PartialResolutionEvidence = parsed.data;

    // 3. ID and repository check
    if (evidence.incidentId !== record.id) {
      reasons.push(`Incident ID mismatch: evidence is for '${evidence.incidentId}', record is '${record.id}'`);
    }

    try {
      const recRepo = normalizeCanonicalRepository(record.canonicalRepository);
      const evRepo = normalizeCanonicalRepository(evidence.canonicalRepository);
      if (recRepo !== evRepo) {
        reasons.push(`Repository isolation violation: evidence is for '${evRepo}', record is '${recRepo}'`);
      }
    } catch (err) {
      reasons.push(`Repository normalization failed: ${String(err)}`);
    }

    // 4. Timestamp check
    const now = options.now ?? new Date();
    const maxAgeMs = options.maxEvidenceAgeMs ?? DEFAULT_MAX_EVIDENCE_AGE_MS;
    const freshness = this.checkTimestampFreshness(evidence.mitigatedAt, now, maxAgeMs);
    if (!freshness.valid) {
      reasons.push(`Mitigation timestamp error: ${freshness.reason}`);
      missingEvidence.push('Valid, unexpired mitigation evidence');
    }

    // 5. Replay check
    const evidenceHash = computeEvidenceHash(evidence);
    if (this.isEvidenceReplayed(record, evidenceHash)) {
      reasons.push(`Duplicate evidence detected: exact payload hash '${evidenceHash}' was previously recorded`);
      missingEvidence.push('Fresh mitigation evidence');
    }

    if (reasons.length > 0) {
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons,
        missingEvidence,
        evidenceHash
      };
    }

    const proposedHistoryEntry: ResolutionHistoryEntry = {
      id: `rh_${Date.now()}_${randomBytes(3).toString('hex')}`,
      fromStatus,
      toStatus,
      timestamp: now.toISOString(),
      evidence: `Partial mitigation: ${evidence.mitigationScope}. Remaining: ${evidence.remainingDefects}. [evidenceHash: ${evidenceHash}]`,
      actor: evidence.provenance.capturedBy
    };

    return {
      valid: true,
      fromStatus,
      toStatus,
      reasons: [
        `Mitigation scope: ${evidence.mitigationScope}`,
        `Documented remaining defects: ${evidence.remainingDefects}`,
        `Evidence fingerprint: ${evidenceHash}`
      ],
      missingEvidence: [],
      evidenceHash,
      proposedHistoryEntry
    };
  }

  /**
   * Verifies regression occurrence evidence.
   */
  public static verifyRegression(
    record: IncidentMemoryRecord,
    evidenceRaw: unknown,
    options: VerificationOptions = {}
  ): StateTransitionResult {
    const fromStatus = record.verificationStatus;
    const toStatus: ResolutionVerificationStatus = 'REGRESSED';
    const reasons: string[] = [];
    const missingEvidence: string[] = [];

    // 1. Transition check
    const transitionCheck = this.checkTransitionAllowed(fromStatus, toStatus);
    if (!transitionCheck.valid) {
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons: [transitionCheck.reason!],
        missingEvidence: ['Allowed state transition path']
      };
    }

    // 2. Schema check
    const parsed = RegressionEvidenceSchema.safeParse(evidenceRaw);
    if (!parsed.success) {
      const fieldErrors = parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`);
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons: ['Regression evidence failed schema validation', ...fieldErrors],
        missingEvidence: fieldErrors
      };
    }

    const evidence: RegressionEvidence = parsed.data;

    // 3. ID and repository check
    if (evidence.incidentId !== record.id) {
      reasons.push(`Incident ID mismatch: evidence is for '${evidence.incidentId}', record is '${record.id}'`);
    }

    try {
      const recRepo = normalizeCanonicalRepository(record.canonicalRepository);
      const evRepo = normalizeCanonicalRepository(evidence.canonicalRepository);
      if (recRepo !== evRepo) {
        reasons.push(`Repository isolation violation: evidence is for '${evRepo}', record is '${recRepo}'`);
      }
    } catch (err) {
      reasons.push(`Repository normalization failed: ${String(err)}`);
    }

    // 4. Timestamp check
    const now = options.now ?? new Date();
    const maxAgeMs = options.maxEvidenceAgeMs ?? DEFAULT_MAX_EVIDENCE_AGE_MS;
    const freshness = this.checkTimestampFreshness(evidence.detectedAt, now, maxAgeMs);
    if (!freshness.valid) {
      reasons.push(`Regression timestamp error: ${freshness.reason}`);
      missingEvidence.push('Valid, unexpired regression evidence');
    }

    // 5. Replay check
    const evidenceHash = computeEvidenceHash(evidence);
    if (this.isEvidenceReplayed(record, evidenceHash)) {
      reasons.push(`Duplicate evidence detected: exact payload hash '${evidenceHash}' was previously recorded`);
      missingEvidence.push('Fresh regression evidence');
    }

    if (reasons.length > 0) {
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons,
        missingEvidence,
        evidenceHash
      };
    }

    const proposedHistoryEntry: ResolutionHistoryEntry = {
      id: `rh_${Date.now()}_${randomBytes(3).toString('hex')}`,
      fromStatus,
      toStatus,
      timestamp: now.toISOString(),
      evidence: `Regression observed: ${evidence.failureReason}. [evidenceHash: ${evidenceHash}]`,
      actor: evidence.provenance.capturedBy
    };

    return {
      valid: true,
      fromStatus,
      toStatus,
      reasons: [
        `Regression detected: ${evidence.failureReason}`,
        `Evidence fingerprint: ${evidenceHash}`
      ],
      missingEvidence: [],
      evidenceHash,
      proposedHistoryEntry
    };
  }

  /**
   * Verifies a proposal iteration (e.g. initial proposal or fresh remediation iteration after regression).
   */
  public static verifyUnverifiedProposal(
    record: IncidentMemoryRecord,
    evidenceRaw: unknown,
    options: VerificationOptions = {}
  ): StateTransitionResult {
    const fromStatus = record.verificationStatus;
    const toStatus: ResolutionVerificationStatus = 'UNVERIFIED_PROPOSAL';
    const reasons: string[] = [];
    const missingEvidence: string[] = [];

    // 1. Transition check
    const transitionCheck = this.checkTransitionAllowed(fromStatus, toStatus);
    if (!transitionCheck.valid) {
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons: [transitionCheck.reason!],
        missingEvidence: ['Allowed state transition path']
      };
    }

    // 2. Schema check
    const parsed = UnverifiedProposalEvidenceSchema.safeParse(evidenceRaw);
    if (!parsed.success) {
      const fieldErrors = parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`);
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons: ['Proposal evidence failed schema validation', ...fieldErrors],
        missingEvidence: fieldErrors
      };
    }

    const evidence: UnverifiedProposalEvidence = parsed.data;

    // 3. ID and repository check
    if (evidence.incidentId !== record.id) {
      reasons.push(`Incident ID mismatch: evidence is for '${evidence.incidentId}', record is '${record.id}'`);
    }

    try {
      const recRepo = normalizeCanonicalRepository(record.canonicalRepository);
      const evRepo = normalizeCanonicalRepository(evidence.canonicalRepository);
      if (recRepo !== evRepo) {
        reasons.push(`Repository isolation violation: evidence is for '${evRepo}', record is '${recRepo}'`);
      }
    } catch (err) {
      reasons.push(`Repository normalization failed: ${String(err)}`);
    }

    // 4. Timestamp check
    const now = options.now ?? new Date();
    const maxAgeMs = options.maxEvidenceAgeMs ?? DEFAULT_MAX_EVIDENCE_AGE_MS;
    const freshness = this.checkTimestampFreshness(evidence.proposedAt, now, maxAgeMs);
    if (!freshness.valid) {
      reasons.push(`Proposal timestamp error: ${freshness.reason}`);
      missingEvidence.push('Valid, unexpired proposal evidence');
    }

    // 5. Replay check
    const evidenceHash = computeEvidenceHash(evidence);
    if (this.isEvidenceReplayed(record, evidenceHash)) {
      reasons.push(`Duplicate evidence detected: exact payload hash '${evidenceHash}' was previously recorded`);
      missingEvidence.push('Fresh proposal evidence');
    }

    if (reasons.length > 0) {
      return {
        valid: false,
        fromStatus,
        toStatus,
        reasons,
        missingEvidence,
        evidenceHash
      };
    }

    const proposedHistoryEntry: ResolutionHistoryEntry = {
      id: `rh_${Date.now()}_${randomBytes(3).toString('hex')}`,
      fromStatus,
      toStatus,
      timestamp: now.toISOString(),
      evidence: `Proposed remediation iteration: ${evidence.proposalSummary}. Proposed diffHash: ${evidence.proposedDiffHash.slice(0, 12)}... [evidenceHash: ${evidenceHash}]`,
      actor: evidence.provenance.capturedBy
    };

    return {
      valid: true,
      fromStatus,
      toStatus,
      reasons: [
        `Proposal summary: ${evidence.proposalSummary}`,
        `Proposed diffHash: ${evidence.proposedDiffHash}`,
        `Evidence fingerprint: ${evidenceHash}`
      ],
      missingEvidence: [],
      evidenceHash,
      proposedHistoryEntry
    };
  }

  /**
   * Unified transition validator dispatching to the appropriate verification method.
   */
  public static validateTransition(
    record: IncidentMemoryRecord,
    toStatus: ResolutionVerificationStatus,
    evidencePayload: unknown,
    options: VerificationOptions = {}
  ): StateTransitionResult {
    switch (toStatus) {
      case 'VERIFIED_RESOLVED':
        return this.verifyFullResolution(record, evidencePayload, options);
      case 'PARTIAL_RESOLUTION':
        return this.verifyPartialResolution(record, evidencePayload, options);
      case 'REGRESSED':
        return this.verifyRegression(record, evidencePayload, options);
      case 'UNVERIFIED_PROPOSAL':
        return this.verifyUnverifiedProposal(record, evidencePayload, options);
      default:
        return {
          valid: false,
          fromStatus: record.verificationStatus,
          toStatus,
          reasons: [`Unsupported destination status: '${String(toStatus)}'`],
          missingEvidence: ['Valid destination status']
        };
    }
  }

  /**
   * Validates whether a state transition path is allowed.
   */
  public static checkTransitionAllowed(
    fromStatus: ResolutionVerificationStatus | undefined,
    toStatus: ResolutionVerificationStatus
  ): { valid: boolean; reason?: string } {
    // Initial state (undefined) can only transition to UNVERIFIED_PROPOSAL
    if (!fromStatus) {
      if (toStatus === 'UNVERIFIED_PROPOSAL') {
        return { valid: true };
      }
      return {
        valid: false,
        reason: `Initial state can only transition to 'UNVERIFIED_PROPOSAL', not '${toStatus}'`
      };
    }

    // Same status transition (duplicate/no-op)
    if (fromStatus === toStatus) {
      return {
        valid: false,
        reason: `Invalid redundant transition: incident is already in status '${fromStatus}'`
      };
    }

    const allowed = ALLOWED_TRANSITIONS[fromStatus];
    if (allowed && allowed.has(toStatus)) {
      return { valid: true };
    }

    return {
      valid: false,
      reason: `Forbidden state transition: cannot transition from '${fromStatus}' to '${toStatus}'`
    };
  }

  /**
   * Checks whether evidence was previously recorded to prevent duplicate or replayed verification events.
   */
  private static isEvidenceReplayed(record: IncidentMemoryRecord, evidenceHash: string): boolean {
    if (!record.resolutionHistory || record.resolutionHistory.length === 0) {
      return false;
    }
    return record.resolutionHistory.some((h) => h.evidence.includes(evidenceHash));
  }

  /**
   * Checks timestamp freshness and prevents future timestamps.
   */
  private static checkTimestampFreshness(
    timestampStr: string,
    now: Date,
    maxAgeMs: number
  ): { valid: boolean; reason?: string } {
    const ts = new Date(timestampStr).getTime();
    if (isNaN(ts)) {
      return { valid: false, reason: `Invalid date format: '${timestampStr}'` };
    }

    const nowMs = now.getTime();
    // Allow up to 30 seconds of clock drift
    if (ts > nowMs + 30_000) {
      return { valid: false, reason: `Timestamp is in the future (${timestampStr})` };
    }

    if (nowMs - ts > maxAgeMs) {
      return {
        valid: false,
        reason: `Evidence is expired (age exceeds ${maxAgeMs / 1000} seconds)`
      };
    }

    return { valid: true };
  }
}

