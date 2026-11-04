import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  ResolutionVerifier,
  IncidentMemoryRecord,
  FullResolutionVerificationBundle,
  PartialResolutionEvidence,
  RegressionEvidence,
  UnverifiedProposalEvidence,
  computeEvidenceHash
} from '../src/memory/index.js';

describe('Sub-Stage 4.3.3.2: ResolutionVerifier & State-Transition Validation', () => {
  const baseRecord: IncidentMemoryRecord = {
    id: 'INC-2026-300',
    canonicalRepository: 'devpulse/core',
    timestamp: '2026-11-04T12:00:00.000Z',
    category: 'RUNTIME_EXCEPTION',
    errorSignature: 'TypeError: Cannot read properties of undefined (reading token)',
    affectedTarget: 'src/auth/jwt.ts',
    rootCause: 'Unchecked null payload in token parser',
    fixSummary: 'Added optional chaining before reading token',
    diffHash: 'a'.repeat(64),
    prLink: 'https://github.com/devpulse/core/pull/101',
    outcome: 'RESOLVED',
    verificationStatus: 'UNVERIFIED_PROPOSAL',
    resolutionHistory: []
  };

  const validFullBundle: FullResolutionVerificationBundle = {
    incidentId: 'INC-2026-300',
    canonicalRepository: 'devpulse/core',
    pr: {
      prNumber: 101,
      prUrl: 'https://github.com/devpulse/core/pull/101',
      baseBranch: 'main',
      mergeCommitSha: '1'.repeat(40),
      mergedAt: '2026-11-04T12:05:00.000Z',
      mergedBy: 'lead-dev',
      provenance: {
        source: 'GITHUB_API',
        sourceReference: 'https://api.github.com/repos/devpulse/core/pulls/101',
        capturedAt: '2026-11-04T12:05:00.000Z',
        verificationType: 'INDEPENDENTLY_VERIFIED',
        evidenceHash: 'b'.repeat(64)
      }
    },
    diff: {
      proposedDiffHash: 'a'.repeat(64),
      actualMergedDiffHash: 'a'.repeat(64),
      isReconciled: false
    },
    regressionTests: {
      testSuiteName: 'tests/auth/token.test.ts',
      command: 'npm test -- tests/auth/token.test.ts',
      executedAt: '2026-11-04T12:08:00.000Z',
      durationMs: 400,
      totalTests: 12,
      passedTests: 12,
      failedTests: 0,
      skippedTests: 0,
      outputLogHash: 'c'.repeat(64),
      provenance: {
        source: 'CI_CD_PIPELINE',
        sourceReference: 'https://ci.devpulse.org/runs/1234',
        capturedAt: '2026-11-04T12:08:00.000Z',
        verificationType: 'INDEPENDENTLY_VERIFIED',
        evidenceHash: 'd'.repeat(64)
      }
    },
    confirmation: {
      confirmedAt: '2026-11-04T12:10:00.000Z',
      observabilityEvidence: {
        metricOrLogRef: 'datadog://monitors/101/error_rate',
        observedAt: '2026-11-04T12:10:00.000Z',
        sampleProof: '0.00% 5xx errors across all pods for 30 minutes',
        provenance: {
          source: 'OBSERVABILITY_SYSTEM',
          sourceReference: 'datadog://monitors/101',
          capturedAt: '2026-11-04T12:10:00.000Z',
          verificationType: 'INDEPENDENTLY_VERIFIED',
          evidenceHash: 'e'.repeat(64)
        }
      },
      provenance: {
        source: 'OBSERVABILITY_SYSTEM',
        sourceReference: 'datadog://monitors/101',
        capturedAt: '2026-11-04T12:10:00.000Z',
        verificationType: 'INDEPENDENTLY_VERIFIED',
        evidenceHash: 'e'.repeat(64)
      }
    }
  };

  const validPartialEvidence: PartialResolutionEvidence = {
    incidentId: 'INC-2026-300',
    canonicalRepository: 'devpulse/core',
    mitigatedAt: '2026-11-04T12:15:00.000Z',
    mitigationScope: 'Applied rate limiting and token cache workaround',
    remainingDefects: 'Core JWT library parser still needs permanent upstream patch',
    provenance: {
      source: 'SWITCH_ROOM',
      sourceReference: 'msg_mitigate_001',
      capturedAt: '2026-11-04T12:15:00.000Z',
      verificationType: 'USER_PROVIDED',
      evidenceHash: 'f'.repeat(64),
      capturedBy: {
        type: 'HUMAN',
        id: 'maintainer_1',
        name: 'Maintainer Bob'
      }
    }
  };

  const validRegressionEvidence: RegressionEvidence = {
    incidentId: 'INC-2026-300',
    canonicalRepository: 'devpulse/core',
    detectedAt: '2026-11-04T12:20:00.000Z',
    failureReason: 'Recurring TypeError after cache invalidation',
    corroboratingIncidentId: 'INC-2026-305',
    provenance: {
      source: 'OBSERVABILITY_SYSTEM',
      sourceReference: 'alert_reopened_99',
      capturedAt: '2026-11-04T12:20:00.000Z',
      verificationType: 'INDEPENDENTLY_VERIFIED',
      evidenceHash: '0'.repeat(64)
    }
  };

  describe('1. Allowed State Transitions Matrix', () => {
    it('allows initial state -> UNVERIFIED_PROPOSAL', () => {
      const result = ResolutionVerifier.checkTransitionAllowed(undefined, 'UNVERIFIED_PROPOSAL');
      assert.equal(result.valid, true);
    });

    it('allows UNVERIFIED_PROPOSAL -> PARTIAL_RESOLUTION, VERIFIED_RESOLVED, and REGRESSED', () => {
      assert.equal(ResolutionVerifier.checkTransitionAllowed('UNVERIFIED_PROPOSAL', 'PARTIAL_RESOLUTION').valid, true);
      assert.equal(ResolutionVerifier.checkTransitionAllowed('UNVERIFIED_PROPOSAL', 'VERIFIED_RESOLVED').valid, true);
      assert.equal(ResolutionVerifier.checkTransitionAllowed('UNVERIFIED_PROPOSAL', 'REGRESSED').valid, true);
    });

    it('allows PARTIAL_RESOLUTION -> VERIFIED_RESOLVED and REGRESSED', () => {
      assert.equal(ResolutionVerifier.checkTransitionAllowed('PARTIAL_RESOLUTION', 'VERIFIED_RESOLVED').valid, true);
      assert.equal(ResolutionVerifier.checkTransitionAllowed('PARTIAL_RESOLUTION', 'REGRESSED').valid, true);
    });

    it('allows VERIFIED_RESOLVED -> REGRESSED', () => {
      assert.equal(ResolutionVerifier.checkTransitionAllowed('VERIFIED_RESOLVED', 'REGRESSED').valid, true);
    });

    it('allows REGRESSED -> UNVERIFIED_PROPOSAL and VERIFIED_RESOLVED', () => {
      assert.equal(ResolutionVerifier.checkTransitionAllowed('REGRESSED', 'UNVERIFIED_PROPOSAL').valid, true);
      assert.equal(ResolutionVerifier.checkTransitionAllowed('REGRESSED', 'VERIFIED_RESOLVED').valid, true);
    });
  });

  describe('2. Forbidden State Transitions', () => {
    it('rejects initial state -> VERIFIED_RESOLVED directly', () => {
      const result = ResolutionVerifier.checkTransitionAllowed(undefined, 'VERIFIED_RESOLVED');
      assert.equal(result.valid, false);
      assert.ok(result.reason?.includes("Initial state can only transition to 'UNVERIFIED_PROPOSAL'"));
    });

    it('rejects VERIFIED_RESOLVED -> UNVERIFIED_PROPOSAL directly', () => {
      const result = ResolutionVerifier.checkTransitionAllowed('VERIFIED_RESOLVED', 'UNVERIFIED_PROPOSAL');
      assert.equal(result.valid, false);
      assert.ok(result.reason?.includes('Forbidden state transition'));
    });

    it('rejects VERIFIED_RESOLVED -> PARTIAL_RESOLUTION (cannot downgrade verified to partial)', () => {
      const result = ResolutionVerifier.checkTransitionAllowed('VERIFIED_RESOLVED', 'PARTIAL_RESOLUTION');
      assert.equal(result.valid, false);
      assert.ok(result.reason?.includes('Forbidden state transition'));
    });

    it('rejects PARTIAL_RESOLUTION -> UNVERIFIED_PROPOSAL', () => {
      const result = ResolutionVerifier.checkTransitionAllowed('PARTIAL_RESOLUTION', 'UNVERIFIED_PROPOSAL');
      assert.equal(result.valid, false);
      assert.ok(result.reason?.includes('Forbidden state transition'));
    });

    it('rejects redundant identical state transitions (no-ops)', () => {
      assert.equal(ResolutionVerifier.checkTransitionAllowed('VERIFIED_RESOLVED', 'VERIFIED_RESOLVED').valid, false);
      assert.equal(ResolutionVerifier.checkTransitionAllowed('UNVERIFIED_PROPOSAL', 'UNVERIFIED_PROPOSAL').valid, false);
      assert.equal(ResolutionVerifier.checkTransitionAllowed('PARTIAL_RESOLUTION', 'PARTIAL_RESOLUTION').valid, false);
      assert.equal(ResolutionVerifier.checkTransitionAllowed('REGRESSED', 'REGRESSED').valid, false);
    });
  });

  describe('3. Full Resolution Verification (VERIFIED_RESOLVED)', () => {
    it('accepts compliant 4-pillar evidence bundle for VERIFIED_RESOLVED transition', () => {
      const result = ResolutionVerifier.verifyFullResolution(baseRecord, validFullBundle, {
        now: new Date('2026-11-04T12:12:00.000Z')
      });

      assert.equal(result.valid, true);
      assert.equal(result.fromStatus, 'UNVERIFIED_PROPOSAL');
      assert.equal(result.toStatus, 'VERIFIED_RESOLVED');
      assert.ok(result.proposedHistoryEntry !== undefined);
      assert.equal(result.proposedHistoryEntry?.toStatus, 'VERIFIED_RESOLVED');
      assert.ok(result.proposedHistoryEntry?.evidence.includes('Verified resolution merged in PR #101'));
      assert.ok(result.evidenceHash !== undefined);
    });

    it('rejects missing PR evidence', () => {
      const missingPR = {
        ...validFullBundle,
        pr: undefined
      };

      const result = ResolutionVerifier.verifyFullResolution(baseRecord, missingPR);
      assert.equal(result.valid, false);
      assert.ok(result.reasons.some((r) => r.includes('Evidence bundle failed schema validation')));
    });

    it('rejects regression test failure (failedTests > 0)', () => {
      const failedTestsBundle: FullResolutionVerificationBundle = {
        ...validFullBundle,
        regressionTests: {
          ...validFullBundle.regressionTests,
          totalTests: 12,
          passedTests: 10,
          failedTests: 2,
          skippedTests: 0
        }
      };

      const result = ResolutionVerifier.verifyFullResolution(baseRecord, failedTestsBundle, {
        now: new Date('2026-11-04T12:12:00.000Z')
      });

      assert.equal(result.valid, false);
      assert.ok(result.reasons.some((r) => r.includes('Regression tests did not demonstrate passing execution')));
    });

    it('rejects skipped-only regression test runs (passedTests === 0)', () => {
      const skippedOnlyBundle: FullResolutionVerificationBundle = {
        ...validFullBundle,
        regressionTests: {
          ...validFullBundle.regressionTests,
          totalTests: 5,
          passedTests: 0,
          failedTests: 0,
          skippedTests: 5
        }
      };

      const result = ResolutionVerifier.verifyFullResolution(baseRecord, skippedOnlyBundle, {
        now: new Date('2026-11-04T12:12:00.000Z')
      });

      assert.equal(result.valid, false);
      assert.ok(result.reasons.some((r) => r.includes('Regression tests did not demonstrate passing execution')));
    });
  });

  describe('4. Diff Integrity & Reconciliation', () => {
    it('rejects evidence when proposedDiffHash does not match record.diffHash', () => {
      const mismatchedProposed: FullResolutionVerificationBundle = {
        ...validFullBundle,
        diff: {
          proposedDiffHash: '9'.repeat(64), // Mismatched
          actualMergedDiffHash: '9'.repeat(64),
          isReconciled: false
        }
      };

      const result = ResolutionVerifier.verifyFullResolution(baseRecord, mismatchedProposed, {
        now: new Date('2026-11-04T12:12:00.000Z')
      });

      assert.equal(result.valid, false);
      assert.ok(result.reasons.some((r) => r.includes('Proposed diffHash mismatch')));
    });

    it('rejects actual merged diff differing from proposed diff without reconciliation', () => {
      const unreconciledMerged: FullResolutionVerificationBundle = {
        ...validFullBundle,
        diff: {
          proposedDiffHash: 'a'.repeat(64),
          actualMergedDiffHash: '8'.repeat(64), // Altered in PR
          isReconciled: false
        }
      };

      const result = ResolutionVerifier.verifyFullResolution(baseRecord, unreconciledMerged, {
        now: new Date('2026-11-04T12:12:00.000Z')
      });

      assert.equal(result.valid, false);
    });

    it('accepts actual merged diff differing when explicitly reconciled with reason and actor', () => {
      const reconciledMerged: FullResolutionVerificationBundle = {
        ...validFullBundle,
        diff: {
          proposedDiffHash: 'a'.repeat(64),
          actualMergedDiffHash: '8'.repeat(64),
          isReconciled: true,
          reconciliationReason: 'PR review requested adding a null-check guard in addition to optional chaining',
          reconciledBy: {
            type: 'HUMAN',
            id: 'senior_lead',
            name: 'Senior Lead'
          }
        }
      };

      const result = ResolutionVerifier.verifyFullResolution(baseRecord, reconciledMerged, {
        now: new Date('2026-11-04T12:12:00.000Z')
      });

      assert.equal(result.valid, true);
    });
  });

  describe('5. Evidence Expiration & Temporal Freshness', () => {
    it('rejects evidence timestamps in the future', () => {
      const futureBundle: FullResolutionVerificationBundle = {
        ...validFullBundle,
        pr: {
          ...validFullBundle.pr,
          mergedAt: '2026-11-05T00:00:00.000Z' // Future date compared to now
        }
      };

      const result = ResolutionVerifier.verifyFullResolution(baseRecord, futureBundle, {
        now: new Date('2026-11-04T12:12:00.000Z')
      });

      assert.equal(result.valid, false);
      assert.ok(result.reasons.some((r) => r.includes('timestamp error') && r.includes('in the future')));
    });

    it('rejects evidence older than maxEvidenceAgeMs (expired evidence)', () => {
      const expiredBundle: FullResolutionVerificationBundle = {
        ...validFullBundle,
        pr: {
          ...validFullBundle.pr,
          mergedAt: '2026-09-01T00:00:00.000Z' // 2 months ago
        }
      };

      const result = ResolutionVerifier.verifyFullResolution(baseRecord, expiredBundle, {
        now: new Date('2026-11-04T12:12:00.000Z'),
        maxEvidenceAgeMs: 7 * 24 * 60 * 60 * 1000 // 7 days max age
      });

      assert.equal(result.valid, false);
      assert.ok(result.reasons.some((r) => r.includes('is expired')));
    });
  });

  describe('6. Replay & Duplicate Evidence Protection', () => {
    it('rejects replayed evidence whose payload hash was already recorded in history', () => {
      const evidenceHash = computeEvidenceHash(validFullBundle);

      // Record already has this evidence recorded in history
      const recordWithHistory: IncidentMemoryRecord = {
        ...baseRecord,
        resolutionHistory: [
          {
            id: 'rh_prev_1',
            fromStatus: 'UNVERIFIED_PROPOSAL',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:10:00.000Z',
            evidence: `Verified resolution merged in PR #101. [evidenceHash: ${evidenceHash}]`
          }
        ]
      };

      const result = ResolutionVerifier.verifyFullResolution(recordWithHistory, validFullBundle, {
        now: new Date('2026-11-04T12:12:00.000Z')
      });

      assert.equal(result.valid, false);
      assert.ok(result.reasons.some((r) => r.includes('Duplicate evidence detected')));
    });
  });

  describe('7. Partial Resolution & Regression Evidence', () => {
    it('verifies legitimate partial mitigation evidence', () => {
      const result = ResolutionVerifier.verifyPartialResolution(baseRecord, validPartialEvidence, {
        now: new Date('2026-11-04T12:16:00.000Z')
      });

      assert.equal(result.valid, true);
      assert.equal(result.fromStatus, 'UNVERIFIED_PROPOSAL');
      assert.equal(result.toStatus, 'PARTIAL_RESOLUTION');
      assert.ok(result.proposedHistoryEntry?.evidence.includes('Partial mitigation'));
    });

    it('verifies regression occurrence evidence from VERIFIED_RESOLVED', () => {
      const verifiedRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'VERIFIED_RESOLVED'
      };

      const result = ResolutionVerifier.verifyRegression(verifiedRecord, validRegressionEvidence, {
        now: new Date('2026-11-04T12:22:00.000Z')
      });

      assert.equal(result.valid, true);
      assert.equal(result.fromStatus, 'VERIFIED_RESOLVED');
      assert.equal(result.toStatus, 'REGRESSED');
      assert.ok(result.proposedHistoryEntry?.evidence.includes('Regression observed'));
    });

    it('rejects regression evidence targeting wrong repository', () => {
      const crossRepoRegression: RegressionEvidence = {
        ...validRegressionEvidence,
        canonicalRepository: 'other-org/other-repo'
      };

      const result = ResolutionVerifier.verifyRegression(baseRecord, crossRepoRegression, {
        now: new Date('2026-11-04T12:22:00.000Z')
      });

      assert.equal(result.valid, false);
      assert.ok(result.reasons.some((r) => r.includes('Repository isolation violation')));
    });
  });

  describe('8. Regression Recovery with Fresh Evidence', () => {
    it('rejects recovering from REGRESSED using the merge commit that previously failed', () => {
      const regressedRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'REGRESSED',
        resolutionHistory: [
          {
            id: 'rh_old_1',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:10:00.000Z',
            evidence: 'Merged in PR #101 (1111111). [evidenceHash: old_hash]'
          },
          {
            id: 'rh_old_2',
            fromStatus: 'VERIFIED_RESOLVED',
            toStatus: 'REGRESSED',
            timestamp: '2026-11-04T12:20:00.000Z',
            evidence: 'Regressed due to cache invalidation issue.'
          }
        ]
      };

      // Bundle reuses commit '1111111'
      const replayedCommitBundle: FullResolutionVerificationBundle = {
        ...validFullBundle,
        pr: {
          ...validFullBundle.pr,
          mergeCommitSha: '1'.repeat(40)
        }
      };

      const result = ResolutionVerifier.verifyFullResolution(regressedRecord, replayedCommitBundle, {
        now: new Date('2026-11-04T12:25:00.000Z')
      });

      assert.equal(result.valid, false);
      assert.ok(result.reasons.some((r) => r.includes('Regressed incident recovery cannot reuse merge commit')));
    });

    it('accepts recovery from REGRESSED using fresh PR, commit SHA, and tests', () => {
      const regressedRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'REGRESSED',
        resolutionHistory: [
          {
            id: 'rh_old_1',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:10:00.000Z',
            evidence: 'Merged in PR #101 (1111111). [evidenceHash: old_hash]'
          },
          {
            id: 'rh_old_2',
            fromStatus: 'VERIFIED_RESOLVED',
            toStatus: 'REGRESSED',
            timestamp: '2026-11-04T12:20:00.000Z',
            evidence: 'Regressed due to cache invalidation issue.'
          }
        ]
      };

      // Fresh fix: PR #102, commit '2222222'
      const freshBundle: FullResolutionVerificationBundle = {
        ...validFullBundle,
        pr: {
          ...validFullBundle.pr,
          prNumber: 102,
          prUrl: 'https://github.com/devpulse/core/pull/102',
          mergeCommitSha: '2'.repeat(40),
          mergedAt: '2026-11-04T12:25:00.000Z'
        },
        regressionTests: {
          ...validFullBundle.regressionTests,
          executedAt: '2026-11-04T12:26:00.000Z'
        },
        confirmation: {
          ...validFullBundle.confirmation,
          confirmedAt: '2026-11-04T12:27:00.000Z'
        }
      };

      const result = ResolutionVerifier.verifyFullResolution(regressedRecord, freshBundle, {
        now: new Date('2026-11-04T12:28:00.000Z')
      });

      assert.equal(result.valid, true);
      assert.equal(result.fromStatus, 'REGRESSED');
      assert.equal(result.toStatus, 'VERIFIED_RESOLVED');
    });

    it('verifies proposing a new remediation iteration from REGRESSED back to UNVERIFIED_PROPOSAL', () => {
      const regressedRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'REGRESSED'
      };

      const newProposal: UnverifiedProposalEvidence = {
        incidentId: 'INC-2026-300',
        canonicalRepository: 'devpulse/core',
        proposedDiffHash: '7'.repeat(64),
        proposalSummary: 'Redesigned token validation to avoid recursive cache lookup',
        proposedAt: '2026-11-04T12:25:00.000Z',
        provenance: {
          source: 'SWITCH_ROOM',
          sourceReference: 'msg_proposal_v2',
          capturedAt: '2026-11-04T12:25:00.000Z',
          verificationType: 'USER_PROVIDED',
          evidenceHash: '7'.repeat(64)
        }
      };

      const result = ResolutionVerifier.verifyUnverifiedProposal(regressedRecord, newProposal, {
        now: new Date('2026-11-04T12:26:00.000Z')
      });

      assert.equal(result.valid, true);
      assert.equal(result.fromStatus, 'REGRESSED');
      assert.equal(result.toStatus, 'UNVERIFIED_PROPOSAL');
    });
  });

  describe('9. Unified validateTransition Dispatcher', () => {
    it('dispatches properly based on destination status', () => {
      const res = ResolutionVerifier.validateTransition(
        baseRecord,
        'PARTIAL_RESOLUTION',
        validPartialEvidence,
        { now: new Date('2026-11-04T12:16:00.000Z') }
      );
      assert.equal(res.valid, true);
      assert.equal(res.toStatus, 'PARTIAL_RESOLUTION');
    });
  });
});

