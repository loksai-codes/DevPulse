import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  MergedPREvidenceSchema,
  RegressionTestEvidenceSchema,
  ResolutionConfirmationSchema,
  DiffIntegrityEvidenceSchema,
  EvidenceProvenanceSchema,
  RegressionEvidenceSchema,
  PartialResolutionEvidenceSchema,
  isRegressionTestExecutionSuccessful,
  computeEvidenceHash
} from '../src/memory/index.js';

describe('Sub-Stage 4.3.3.1: Resolution Evidence Schemas & Provenance Contracts', () => {
  const validProvenance = {
    source: 'GITHUB_API' as const,
    sourceReference: 'https://api.github.com/repos/devpulse/core/pulls/101',
    capturedAt: '2026-11-04T12:00:00.000Z',
    verificationType: 'INDEPENDENTLY_VERIFIED' as const,
    evidenceHash: 'a'.repeat(64),
    capturedBy: {
      type: 'SYSTEM' as const,
      id: 'sys_gh_webhook',
      name: 'GitHub Webhook Receiver'
    }
  };

  describe('1. Merged PR Evidence Validation', () => {
    it('validates legitimate merged PR evidence', () => {
      const validPR = {
        prNumber: 101,
        prUrl: 'https://github.com/devpulse/core/pull/101',
        baseBranch: 'main',
        mergeCommitSha: 'e'.repeat(40),
        mergedAt: '2026-11-04T12:05:00.000Z',
        mergedBy: 'octocat',
        provenance: validProvenance
      };

      assert.doesNotThrow(() => MergedPREvidenceSchema.parse(validPR));
    });

    it('rejects invalid PR evidence (invalid PR number, malformed URL, empty base branch)', () => {
      const invalidNumber = {
        prNumber: -5,
        prUrl: 'https://github.com/devpulse/core/pull/101',
        baseBranch: 'main',
        mergeCommitSha: 'e'.repeat(40),
        mergedAt: '2026-11-04T12:05:00.000Z',
        mergedBy: 'octocat',
        provenance: validProvenance
      };
      assert.throws(() => MergedPREvidenceSchema.parse(invalidNumber), /prNumber must be a positive integer/);

      const invalidUrl = {
        ...invalidNumber,
        prNumber: 101,
        prUrl: 'not-a-valid-url'
      };
      assert.throws(() => MergedPREvidenceSchema.parse(invalidUrl), /prUrl must be a valid URL/);

      const emptyBranch = {
        ...invalidNumber,
        prNumber: 101,
        baseBranch: ''
      };
      assert.throws(() => MergedPREvidenceSchema.parse(emptyBranch), /baseBranch cannot be empty/);
    });

    it('rejects invalid commit hashes (short hashes, non-hex characters)', () => {
      const shortSha = {
        prNumber: 101,
        prUrl: 'https://github.com/devpulse/core/pull/101',
        baseBranch: 'main',
        mergeCommitSha: 'abc1234', // short hash
        mergedAt: '2026-11-04T12:05:00.000Z',
        mergedBy: 'octocat',
        provenance: validProvenance
      };
      assert.throws(() => MergedPREvidenceSchema.parse(shortSha), /mergeCommitSha must be a 40-64 character hexadecimal commit SHA/);

      const nonHexSha = {
        ...shortSha,
        mergeCommitSha: 'z'.repeat(40)
      };
      assert.throws(() => MergedPREvidenceSchema.parse(nonHexSha), /mergeCommitSha must be a 40-64 character hexadecimal commit SHA/);
    });
  });

  describe('2. Regression Test Evidence & Count Consistency', () => {
    const validTestProvenance = {
      source: 'CI_CD_PIPELINE' as const,
      sourceReference: 'https://ci.devpulse.org/runs/8892',
      capturedAt: '2026-11-04T12:10:00.000Z',
      verificationType: 'INDEPENDENTLY_VERIFIED' as const,
      evidenceHash: 'b'.repeat(64)
    };

    it('validates compliant regression test evidence with consistent counts', () => {
      const validTest = {
        testSuiteName: 'tests/auth/token.test.ts',
        command: 'npm test -- tests/auth/token.test.ts',
        executedAt: '2026-11-04T12:08:00.000Z',
        durationMs: 450,
        totalTests: 10,
        passedTests: 9,
        failedTests: 0,
        skippedTests: 1,
        outputLogHash: 'c'.repeat(64),
        provenance: validTestProvenance
      };

      const parsed = RegressionTestEvidenceSchema.parse(validTest);
      assert.equal(parsed.totalTests, 10);
      assert.equal(isRegressionTestExecutionSuccessful(parsed), true);
    });

    it('rejects inconsistent test counts (totalTests !== passed + failed + skipped)', () => {
      const inconsistentCounts = {
        testSuiteName: 'tests/unit.test.ts',
        command: 'npm test',
        executedAt: '2026-11-04T12:08:00.000Z',
        durationMs: 450,
        totalTests: 20, // claims 20, but sum is 10 + 0 + 0 = 10
        passedTests: 10,
        failedTests: 0,
        skippedTests: 0,
        outputLogHash: 'c'.repeat(64),
        provenance: validTestProvenance
      };

      assert.throws(
        () => RegressionTestEvidenceSchema.parse(inconsistentCounts),
        /Inconsistent test counts: totalTests must strictly equal passedTests \+ failedTests \+ skippedTests/
      );
    });

    it('refuses to treat skipped-only test suites as successful executions', () => {
      const skippedOnlyTest = {
        testSuiteName: 'tests/skipped.test.ts',
        command: 'npm test',
        executedAt: '2026-11-04T12:08:00.000Z',
        durationMs: 12,
        totalTests: 5,
        passedTests: 0,
        failedTests: 0,
        skippedTests: 5,
        outputLogHash: 'd'.repeat(64),
        provenance: validTestProvenance
      };

      const parsed = RegressionTestEvidenceSchema.parse(skippedOnlyTest);
      // Even though failedTests is 0, passedTests is 0 so it does not establish genuine recovery execution!
      assert.equal(isRegressionTestExecutionSuccessful(parsed), false);
    });

    it('rejects test runs containing failures even if some tests passed', () => {
      const runWithFailures = {
        testSuiteName: 'tests/failing.test.ts',
        command: 'npm test',
        executedAt: '2026-11-04T12:08:00.000Z',
        durationMs: 350,
        totalTests: 10,
        passedTests: 8,
        failedTests: 2,
        skippedTests: 0,
        outputLogHash: 'e'.repeat(64),
        provenance: validTestProvenance
      };

      const parsed = RegressionTestEvidenceSchema.parse(runWithFailures);
      assert.equal(parsed.failedTests, 2);
      assert.equal(isRegressionTestExecutionSuccessful(parsed), false);
    });

    it('handles runs with both passed and skipped tests without classifying skipped as passed', () => {
      const runWithPassedAndSkipped = {
        testSuiteName: 'tests/mixed.test.ts',
        command: 'npm test',
        executedAt: '2026-11-04T12:08:00.000Z',
        durationMs: 500,
        totalTests: 15,
        passedTests: 12,
        failedTests: 0,
        skippedTests: 3,
        outputLogHash: 'a'.repeat(64),
        provenance: validTestProvenance
      };

      const parsed = RegressionTestEvidenceSchema.parse(runWithPassedAndSkipped);
      // Ensure skipped tests remain distinct and are not counted towards passedTests
      assert.equal(parsed.passedTests, 12);
      assert.equal(parsed.skippedTests, 3);
      assert.notEqual(parsed.passedTests, parsed.totalTests);
      assert.equal(isRegressionTestExecutionSuccessful(parsed), true);
    });
  });

  describe('3. Resolution Confirmation & Recovery Proof', () => {
    it('validates automated observability recovery evidence', () => {
      const obsConfirmation = {
        confirmedAt: '2026-11-04T12:15:00.000Z',
        observabilityEvidence: {
          metricOrLogRef: 'datadog://monitors/12345/error_rate',
          observedAt: '2026-11-04T12:14:00.000Z',
          query: 'sum:service.http.5xx{env:prod}.as_count()',
          sampleProof: 'Error rate dropped to 0.00% across all nodes over 15-minute window',
          provenance: {
            source: 'OBSERVABILITY_SYSTEM' as const,
            sourceReference: 'https://app.datadoghq.com/dashboard/123',
            capturedAt: '2026-11-04T12:15:00.000Z',
            verificationType: 'INDEPENDENTLY_VERIFIED' as const,
            evidenceHash: 'f'.repeat(64)
          }
        },
        provenance: {
          source: 'OBSERVABILITY_SYSTEM' as const,
          sourceReference: 'datadog://monitors/12345',
          capturedAt: '2026-11-04T12:15:00.000Z',
          verificationType: 'INDEPENDENTLY_VERIFIED' as const,
          evidenceHash: 'f'.repeat(64)
        }
      };

      assert.doesNotThrow(() => ResolutionConfirmationSchema.parse(obsConfirmation));
    });

    it('validates human confirmation with verified maintainer details', () => {
      const humanConf = {
        confirmedAt: '2026-11-04T12:15:00.000Z',
        humanConfirmation: {
          actor: {
            type: 'HUMAN' as const,
            id: 'lead_dev_42',
            name: 'Principal Engineer'
          },
          confirmedAt: '2026-11-04T12:15:00.000Z',
          notes: 'Customer login flows manually verified in staging and production'
        },
        provenance: {
          source: 'SWITCH_ROOM' as const,
          sourceReference: 'msg_confirm_001',
          capturedAt: '2026-11-04T12:15:00.000Z',
          verificationType: 'USER_PROVIDED' as const,
          evidenceHash: '1'.repeat(64)
        }
      };

      assert.doesNotThrow(() => ResolutionConfirmationSchema.parse(humanConf));
    });

    it('rejects free-text recovery description without structured observability or human confirmation', () => {
      const freeTextOnly = {
        confirmedAt: '2026-11-04T12:15:00.000Z',
        freeTextDescription: 'Everything seems fine now, trust me',
        // Neither humanConfirmation nor observabilityEvidence provided
        provenance: {
          source: 'USER_ASSERTION' as const,
          sourceReference: 'chat_input',
          capturedAt: '2026-11-04T12:15:00.000Z',
          verificationType: 'USER_PROVIDED' as const,
          evidenceHash: '2'.repeat(64)
        }
      };

      assert.throws(
        () => ResolutionConfirmationSchema.parse(freeTextOnly),
        /A free-text recovery description alone cannot establish verified recovery/
      );
    });
  });

  describe('4. Diff Integrity Contract & Reconciliation', () => {
    it('accepts matching proposed and actual merged diff hashes without reconciliation', () => {
      const matching = {
        proposedDiffHash: '3'.repeat(64),
        actualMergedDiffHash: '3'.repeat(64)
      };

      assert.doesNotThrow(() => DiffIntegrityEvidenceSchema.parse(matching));
    });

    it('rejects mismatched diff hashes when isReconciled is false or missing', () => {
      const mismatched = {
        proposedDiffHash: '3'.repeat(64),
        actualMergedDiffHash: '4'.repeat(64),
        isReconciled: false
      };

      assert.throws(
        () => DiffIntegrityEvidenceSchema.parse(mismatched),
        /Mismatched proposed and merged diff hashes require explicit reconciliation/
      );
    });

    it('accepts mismatched diff hashes when explicitly reconciled with reason and acting authority', () => {
      const reconciled = {
        proposedDiffHash: '3'.repeat(64),
        actualMergedDiffHash: '4'.repeat(64),
        isReconciled: true,
        reconciliationReason: 'PR review requested adding a null-check guard in addition to optional chaining',
        reconciledBy: {
          type: 'HUMAN' as const,
          id: 'lead_engineer',
          name: 'Lead Engineer'
        }
      };

      assert.doesNotThrow(() => DiffIntegrityEvidenceSchema.parse(reconciled));
    });
  });

  describe('5. Evidence Provenance & Trust Classification', () => {
    it('rejects claiming INDEPENDENTLY_VERIFIED with USER_ASSERTION source', () => {
      const dishonestProvenance = {
        source: 'USER_ASSERTION' as const,
        sourceReference: 'user_comment',
        capturedAt: '2026-11-04T12:00:00.000Z',
        verificationType: 'INDEPENDENTLY_VERIFIED' as const, // Dishonest claim
        evidenceHash: '5'.repeat(64)
      };

      assert.throws(
        () => EvidenceProvenanceSchema.parse(dishonestProvenance),
        /Evidence with source 'USER_ASSERTION' cannot claim 'INDEPENDENTLY_VERIFIED'/
      );
    });

    it('accepts USER_PROVIDED verification type with USER_ASSERTION source', () => {
      const honestUserProvided = {
        source: 'USER_ASSERTION' as const,
        sourceReference: 'slack_thread_123',
        capturedAt: '2026-11-04T12:00:00.000Z',
        verificationType: 'USER_PROVIDED' as const,
        evidenceHash: '5'.repeat(64)
      };

      assert.doesNotThrow(() => EvidenceProvenanceSchema.parse(honestUserProvided));
    });

    it('rejects invalid or non-ISO timestamps in provenance', () => {
      const invalidTimestamp = {
        source: 'GITHUB_API' as const,
        sourceReference: 'api_ref',
        capturedAt: 'Wednesday noon', // non-ISO
        verificationType: 'INDEPENDENTLY_VERIFIED' as const,
        evidenceHash: '6'.repeat(64)
      };

      assert.throws(() => EvidenceProvenanceSchema.parse(invalidTimestamp), /capturedAt must be an ISO-8601 string/);
    });
  });

  describe('6. Regression and Partial Resolution Schemas', () => {
    it('validates regression evidence with failure reason and provenance', () => {
      const reg = {
        incidentId: 'INC-2026-101',
        canonicalRepository: 'devpulse/core',
        detectedAt: '2026-11-04T13:00:00.000Z',
        failureReason: 'Recurring TypeError after service restart in node pool B',
        corroboratingIncidentId: 'INC-2026-109',
        provenance: validProvenance
      };

      assert.doesNotThrow(() => RegressionEvidenceSchema.parse(reg));
    });

    it('validates partial resolution evidence with scope and remaining defects', () => {
      const partial = {
        incidentId: 'INC-2026-101',
        canonicalRepository: 'devpulse/core',
        mitigatedAt: '2026-11-04T12:30:00.000Z',
        mitigationScope: 'Applied rate limiting to reduce traffic to failing endpoint by 80%',
        remainingDefects: 'Root cause in JWT library still needs upstream dependency patch',
        provenance: {
          ...validProvenance,
          source: 'SWITCH_ROOM' as const,
          verificationType: 'USER_PROVIDED' as const
        }
      };

      assert.doesNotThrow(() => PartialResolutionEvidenceSchema.parse(partial));
    });
  });

  describe('7. Sensitive Credential Redaction in Evidence Hashing', () => {
    it('redacts tokens and credentials before generating evidence hash', () => {
      const payloadWithSecret = {
        prUrl: 'https://github.com/devpulse/core/pull/101?token=ghp_123456789012345678901234567890123456',
        secretPass: 'postgres://admin:superSecret123@db.internal:5432/main'
      };

      const hash = computeEvidenceHash(payloadWithSecret);
      assert.equal(typeof hash, 'string');
      assert.equal(hash.length, 64);

      // Verify that the hash does not change if only the secret portion changes
      const payloadWithDifferentSecret = {
        prUrl: 'https://github.com/devpulse/core/pull/101?token=ghp_999999999999999999999999999999999999',
        secretPass: 'postgres://admin:otherPassword456@db.internal:5432/main'
      };

      const hash2 = computeEvidenceHash(payloadWithDifferentSecret);
      // Because both are redacted to [REDACTED_CREDENTIAL], the canonical sanitized JSON is identical
      assert.equal(hash, hash2);
    });
  });
});

