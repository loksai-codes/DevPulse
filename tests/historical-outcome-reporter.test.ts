import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import {
  IncidentMemoryRecord,
  IncidentMemoryQuery,
  HistoricalIncidentMatch
} from '../src/memory/types.js';
import {
  evaluateIncidentSimilarity,
  rankHistoricalMatches
} from '../src/memory/similarity-engine.js';
import {
  generateHistoricalOutcomeReport,
  formatOutcomeReportMarkdown
} from '../src/memory/historical-outcome-reporter.js';
import { IncidentStore } from '../src/memory/incident-store.js';

describe('Sub-Stage 4.3.3.4: Historical Outcome Reporting & Similarity Integration', () => {
  const baseRecord: IncidentMemoryRecord = {
    id: 'INC-2026-HIST-01',
    canonicalRepository: 'devpulse/core',
    timestamp: '2026-11-04T12:00:00.000Z',
    category: 'RUNTIME_EXCEPTION',
    affectedTarget: 'src/auth/jwt.ts',
    errorSignature: 'Error: TokenExpiredError: jwt expired at verifyToken',
    rootCause: 'Token expiration window was 0 seconds due to invalid environment config',
    fixSummary: 'Set default JWT expiration to 3600 seconds and added fallback verification',
    diffHash: 'a'.repeat(64),
    prLink: 'https://github.com/devpulse/core/pull/101',
    outcome: 'RESOLVED',
    verificationStatus: 'VERIFIED_RESOLVED',
    resolutionHistory: []
  };

  const query: IncidentMemoryQuery = {
    canonicalRepository: 'devpulse/core',
    errorSignature: 'Error: TokenExpiredError: jwt expired at verifyToken',
    category: 'RUNTIME_EXCEPTION',
    affectedTarget: 'src/auth/jwt.ts',
    minSimilarityScore: 0.60,
    maxResults: 5
  };

  describe('1. Verified Historical Resolution', () => {
    it('generates outcome report with PROVEN_FIX_AVAILABLE for verified incident', () => {
      const verifiedRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'VERIFIED_RESOLVED',
        outcome: 'RESOLVED',
        resolutionHistory: [
          {
            id: 'evt_init_01',
            toStatus: 'UNVERIFIED_PROPOSAL',
            timestamp: '2026-11-04T12:05:00.000Z',
            evidence: 'Proposed JWT timeout patch [evidenceHash: ' + '1'.repeat(64) + ']',
            actor: { type: 'SENTINEL', id: 'agent_sentinel', name: 'Sentinel Agent' }
          },
          {
            id: 'evt_verify_02',
            fromStatus: 'UNVERIFIED_PROPOSAL',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:15:00.000Z',
            evidence: 'Verified resolution merged in PR #101 (a1b2c3d) with 15 passing tests. [evidenceHash: ' + '2'.repeat(64) + ']',
            actor: { type: 'SYSTEM', id: 'verifier', name: 'Automated Verifier' }
          }
        ]
      };

      const match = evaluateIncidentSimilarity(query, verifiedRecord);
      assert.ok(match !== null);
      assert.equal(match.outcomeReport.classification, 'VERIFIED_RESOLVED');
      assert.equal(match.outcomeReport.recommendationAdvisory, 'PROVEN_FIX_AVAILABLE');
      assert.equal(match.outcomeReport.isRegressed, false);
      assert.equal(match.outcomeReport.doNotReuseAsProvenFix, false);
      assert.equal(match.outcomeReport.evidenceProvenanceSummary.hasPassingRegressionTests, true);
      assert.equal(match.outcomeReport.evidenceProvenanceSummary.hasMergedPrEvidence, true);
      assert.equal(match.outcomeReport.chronologicalTransitions.length, 2);

      const md = formatOutcomeReportMarkdown(match.outcomeReport);
      assert.ok(md.includes('PROVEN_FIX_AVAILABLE'));
      assert.ok(md.includes('PR #101'));
      assert.ok(!md.includes('CRITICAL WARNING'));
    });
  });

  describe('2. Partial Resolution', () => {
    it('generates outcome report with PARTIAL_MITIGATION_ONLY advisory', () => {
      const partialRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'PARTIAL_RESOLUTION',
        outcome: 'PARTIAL',
        resolutionHistory: [
          {
            id: 'evt_partial_01',
            toStatus: 'PARTIAL_RESOLUTION',
            timestamp: '2026-11-04T12:10:00.000Z',
            evidence: 'Applied temporary rate limit mitigation [evidenceHash: ' + '3'.repeat(64) + ']',
            actor: { type: 'HUMAN', id: 'user_bob', name: 'Bob Maintainer' }
          }
        ]
      };

      const match = evaluateIncidentSimilarity(query, partialRecord);
      assert.ok(match !== null);
      assert.equal(match.outcomeReport.classification, 'PARTIAL_RESOLUTION');
      assert.equal(match.outcomeReport.recommendationAdvisory, 'PARTIAL_MITIGATION_ONLY');
      assert.equal(match.outcomeReport.doNotReuseAsProvenFix, false);
      assert.ok(match.outcomeReport.evidenceProvenanceSummary.missingOrUnavailableEvidence.length > 0);

      const md = formatOutcomeReportMarkdown(match.outcomeReport);
      assert.ok(md.includes('PARTIAL_MITIGATION_ONLY'));
    });
  });

  describe('3. Regressed Incident (Safeguard Enforcement)', () => {
    it('strictly flags currently regressed incidents with REGRESSED_FIX_DO_NOT_REUSE and doNotReuseAsProvenFix: true', () => {
      const regressedRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'REGRESSED',
        outcome: 'REGRESSED',
        resolutionHistory: [
          {
            id: 'evt_res_01',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:10:00.000Z',
            evidence: 'Verified resolution merged in PR #101 with 12 passing tests [evidenceHash: ' + '4'.repeat(64) + ']',
            actor: { type: 'SYSTEM', id: 'verifier', name: 'Automated Verifier' }
          },
          {
            id: 'evt_regr_02',
            fromStatus: 'VERIFIED_RESOLVED',
            toStatus: 'REGRESSED',
            timestamp: '2026-11-04T12:30:00.000Z',
            evidence: 'Regression detected: TokenExpiredError reappeared in production canary [evidenceHash: ' + '5'.repeat(64) + ']',
            actor: { type: 'SENTINEL', id: 'sentinel', name: 'Sentinel Monitor' }
          }
        ]
      };

      const match = evaluateIncidentSimilarity(query, regressedRecord);
      assert.ok(match !== null);
      // Classification reflects CURRENT status
      assert.equal(match.outcomeReport.currentStatus, 'REGRESSED');
      assert.equal(match.outcomeReport.classification, 'REGRESSED');
      assert.equal(match.outcomeReport.isRegressed, true);
      assert.equal(match.outcomeReport.hasHistoricalRegression, true);
      assert.equal(match.outcomeReport.doNotReuseAsProvenFix, true);
      assert.equal(match.outcomeReport.recommendationAdvisory, 'REGRESSED_FIX_DO_NOT_REUSE');
      assert.notEqual(match.outcomeReport.recommendationAdvisory, 'PROVEN_FIX_AVAILABLE');

      const md = formatOutcomeReportMarkdown(match.outcomeReport);
      assert.ok(md.includes('REGRESSED_FIX_DO_NOT_REUSE'));
      assert.ok(md.includes('CRITICAL WARNING'));
      assert.ok(md.includes('Do NOT recommend this remediation as a proven fix'));
    });

    it('reflects VERIFIED_RESOLVED accurately when a historically regressed incident recovers with fresh evidence, while retaining hasHistoricalRegression: true and historical regression warning', () => {
      const recoveredRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'VERIFIED_RESOLVED',
        outcome: 'RESOLVED',
        resolutionHistory: [
          {
            id: 'evt_01',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:00:00.000Z',
            evidence: 'Initial fix merged in PR #101 [evidenceHash: ' + '1'.repeat(64) + ']'
          },
          {
            id: 'evt_02',
            fromStatus: 'VERIFIED_RESOLVED',
            toStatus: 'REGRESSED',
            timestamp: '2026-11-04T12:10:00.000Z',
            evidence: 'Regression reported in canary [evidenceHash: ' + '2'.repeat(64) + ']'
          },
          {
            id: 'evt_03',
            fromStatus: 'REGRESSED',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:30:00.000Z',
            evidence: 'Verified resolution merged in PR #105 with 20 passing tests. [evidenceHash: ' + '3'.repeat(64) + ']'
          }
        ]
      };

      const report = generateHistoricalOutcomeReport(recoveredRecord);
      // 1. Classification reflects current resolution status
      assert.equal(report.currentStatus, 'VERIFIED_RESOLVED');
      assert.equal(report.classification, 'VERIFIED_RESOLVED');

      // 2. hasHistoricalRegression preserves prior regression occurrence (never erased!)
      assert.equal(report.hasHistoricalRegression, true);
      assert.equal(report.isRegressed, false); // not currently regressed
      assert.equal(report.doNotReuseAsProvenFix, false);
      assert.equal(report.recommendationAdvisory, 'PROVEN_FIX_AVAILABLE');

      // 3. Markdown retains the historical regression warning
      const md = formatOutcomeReportMarkdown(report);
      assert.ok(md.includes('HISTORICAL REGRESSION WARNING'));
      assert.ok(md.includes('prior regression in its lifecycle before resolution was verified with fresh evidence'));
      assert.ok(!md.includes('This incident is currently in a **REGRESSED** state'));
    });
  });

  describe('4. Unverified Proposal', () => {
    it('generates report with UNVERIFIED_PROPOSAL_ONLY for unverified proposal', () => {
      const proposalRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'UNVERIFIED_PROPOSAL',
        outcome: 'PENDING',
        resolutionHistory: []
      };

      const match = evaluateIncidentSimilarity(query, proposalRecord);
      assert.ok(match !== null);
      assert.equal(match.outcomeReport.classification, 'UNVERIFIED_PROPOSAL');
      assert.equal(match.outcomeReport.recommendationAdvisory, 'UNVERIFIED_PROPOSAL_ONLY');
      assert.equal(match.outcomeReport.doNotReuseAsProvenFix, false);
      assert.ok(
        match.outcomeReport.evidenceProvenanceSummary.missingOrUnavailableEvidence.some((m) =>
          m.includes('Remediation verification bundle')
        )
      );
    });
  });

  describe('5. Missing Evidence & Incomplete History', () => {
    it('handles records with empty resolution history and identifies missing items', () => {
      const bareRecord: IncidentMemoryRecord = {
        ...baseRecord,
        prLink: '', // Missing PR
        resolutionHistory: []
      };

      const report = generateHistoricalOutcomeReport(bareRecord);
      assert.equal(report.rawHistoryCount, 0);
      assert.equal(report.chronologicalTransitions.length, 0);
      assert.ok(report.evidenceProvenanceSummary.missingOrUnavailableEvidence.includes('Merged PR reference'));
      assert.ok(
        report.evidenceProvenanceSummary.missingOrUnavailableEvidence.some((e) =>
          e.includes('Passing regression test')
        )
      );

      const md = formatOutcomeReportMarkdown(report);
      assert.ok(md.includes('(No recorded transitions)'));
    });
  });

  describe('6. Human Assertion versus Independently Verified Evidence', () => {
    it('distinguishes operator assertion from independent automated verification', () => {
      const humanAssertionRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'PARTIAL_RESOLUTION',
        resolutionHistory: [
          {
            id: 'evt_human_01',
            toStatus: 'PARTIAL_RESOLUTION',
            timestamp: '2026-11-04T12:10:00.000Z',
            evidence: 'Maintainer confirmed hotfix manually in Switch Console. source: USER_ASSERTION [evidenceHash: ' + '7'.repeat(64) + ']',
            actor: { type: 'HUMAN', id: 'user_alice', name: 'Alice Operator' }
          }
        ]
      };

      const report = generateHistoricalOutcomeReport(humanAssertionRecord);
      // Underlying provenance must strictly be USER_ASSERTION
      assert.equal(report.evidenceProvenanceSummary.verificationType, 'USER_ASSERTION');
      // USER_PROVIDED is only a display label, never a third verification type
      assert.equal(report.evidenceProvenanceSummary.displayLabel, 'USER_PROVIDED');
      assert.notEqual(report.evidenceProvenanceSummary.verificationType, 'USER_PROVIDED');
      assert.equal(report.evidenceProvenanceSummary.hasHumanConfirmation, true);
      assert.equal(report.evidenceProvenanceSummary.hasPassingRegressionTests, false);

      const md = formatOutcomeReportMarkdown(report);
      assert.ok(md.includes('`USER_ASSERTION` (USER_PROVIDED)'));
      assert.ok(md.includes('human operator assertion without independent automated regression test verification'));
    });

    it('classifies automated verifier as INDEPENDENTLY_VERIFIED', () => {
      const automatedRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'VERIFIED_RESOLVED',
        resolutionHistory: [
          {
            id: 'evt_auto_01',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:15:00.000Z',
            evidence: 'CI pipeline run passed 10 passing tests. source: CI_CD_PIPELINE INDEPENDENTLY_VERIFIED [evidenceHash: ' + '8'.repeat(64) + ']',
            actor: { type: 'SYSTEM', id: 'ci_runner', name: 'CI/CD Pipeline' }
          }
        ]
      };

      const report = generateHistoricalOutcomeReport(automatedRecord);
      assert.equal(report.evidenceProvenanceSummary.verificationType, 'INDEPENDENTLY_VERIFIED');
      assert.equal(report.evidenceProvenanceSummary.hasPassingRegressionTests, true);
    });
  });

  describe('7. Repository Isolation in Retrieval & Reporting', () => {
    it('strictly isolates incidents across canonical repositories', () => {
      const crossRepoRecord: IncidentMemoryRecord = {
        ...baseRecord,
        canonicalRepository: 'devpulse/runner' // Different repo
      };

      const match = evaluateIncidentSimilarity(query, crossRepoRecord);
      assert.equal(match, null); // Cross-repository match rejected
    });
  });

  describe('8. Multiple Chronological Transitions with Tie-Breaking', () => {
    it('orders transitions strictly ascending by timestamp and uses eventId tie-breaker', () => {
      const multiTransitionRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'PARTIAL_RESOLUTION',
        resolutionHistory: [
          // Out-of-order in raw array
          {
            id: 'evt_step_03',
            toStatus: 'PARTIAL_RESOLUTION',
            timestamp: '2026-11-04T12:20:00.000Z',
            evidence: 'Third transition'
          },
          {
            id: 'evt_step_01_b',
            toStatus: 'UNVERIFIED_PROPOSAL',
            timestamp: '2026-11-04T12:00:00.000Z', // Identical timestamp
            evidence: 'First transition tie B'
          },
          {
            id: 'evt_step_01_a',
            toStatus: 'UNVERIFIED_PROPOSAL',
            timestamp: '2026-11-04T12:00:00.000Z', // Identical timestamp
            evidence: 'First transition tie A'
          },
          {
            id: 'evt_step_02',
            toStatus: 'UNVERIFIED_PROPOSAL',
            timestamp: '2026-11-04T12:10:00.000Z',
            evidence: 'Second transition'
          }
        ]
      };

      const report = generateHistoricalOutcomeReport(multiTransitionRecord);
      assert.equal(report.chronologicalTransitions.length, 4);

      // Verify chronological ordering
      assert.equal(report.chronologicalTransitions[0]?.eventId, 'evt_step_01_a'); // tie-breaker a < b
      assert.equal(report.chronologicalTransitions[1]?.eventId, 'evt_step_01_b');
      assert.equal(report.chronologicalTransitions[2]?.eventId, 'evt_step_02');
      assert.equal(report.chronologicalTransitions[3]?.eventId, 'evt_step_03');
    });
  });

  describe('9. Restart-Loaded History Outcome Reporting', () => {
    it('produces accurate outcome report from restart-loaded IncidentStore records', async () => {
      const tempDir = path.resolve('./temp_test_outcome_report_' + Date.now());
      await fs.mkdir(tempDir, { recursive: true });
      const jsonlPath = path.join(tempDir, 'incidents.jsonl');
      const mdPath = path.join(tempDir, 'incidents.md');
      const quarPath = path.join(tempDir, 'incidents.quarantine.jsonl');

      try {
        // Step 1: Initialize store, append record, and transition it
        const store1 = new IncidentStore({ jsonlPath, markdownPath: mdPath, quarantinePath: quarPath });
        await store1.init();
        await store1.append({
          ...baseRecord,
          verificationStatus: 'UNVERIFIED_PROPOSAL',
          resolutionHistory: []
        });

        const partialEvidence = {
          incidentId: 'INC-2026-HIST-01',
          canonicalRepository: 'devpulse/core',
          mitigationScope: 'Rate limit reduced to 10 req/s',
          remainingDefects: 'Root cause in jwt config remains open',
          mitigatedAt: '2026-11-04T12:15:00.000Z',
          provenance: {
            source: 'SWITCH_ROOM' as const,
            sourceReference: 'room_msg_001',
            capturedAt: '2026-11-04T12:15:00.000Z',
            verificationType: 'USER_PROVIDED' as const,
            evidenceHash: '9'.repeat(64),
            capturedBy: { type: 'HUMAN' as const, id: 'alice', name: 'Alice Maintainer' }
          }
        };

        await store1.transitionResolutionStatus({
          canonicalRepository: 'devpulse/core',
          incidentId: 'INC-2026-HIST-01',
          toStatus: 'PARTIAL_RESOLUTION',
          evidencePayload: partialEvidence,
          eventId: 'evt_persisted_01',
          options: { now: new Date('2026-11-04T12:20:00.000Z') }
        });

        // Step 2: Restart store
        const store2 = new IncidentStore({ jsonlPath, markdownPath: mdPath, quarantinePath: quarPath });
        await store2.init();

        const reloadedRecord = store2.getById('devpulse/core', 'INC-2026-HIST-01');
        assert.ok(reloadedRecord !== null);
        assert.equal(reloadedRecord.verificationStatus, 'PARTIAL_RESOLUTION');
        assert.equal(reloadedRecord.resolutionHistory.length, 1);

        // Step 3: Generate outcome report and evaluate similarity
        const match = evaluateIncidentSimilarity(query, reloadedRecord);
        assert.ok(match !== null);
        assert.equal(match.outcomeReport.classification, 'PARTIAL_RESOLUTION');
        assert.equal(match.outcomeReport.recommendationAdvisory, 'PARTIAL_MITIGATION_ONLY');
        assert.equal(match.outcomeReport.chronologicalTransitions.length, 1);
        assert.equal(match.outcomeReport.chronologicalTransitions[0]?.eventId, 'evt_persisted_01');
      } finally {
        await fs.rm(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe('10. Similarity Scoring Invariance Safeguard', () => {
    it('proves similarity score and exact-match classification are identical regardless of resolution status', () => {
      const verifiedRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'VERIFIED_RESOLVED'
      };

      const regressedRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'REGRESSED'
      };

      const proposalRecord: IncidentMemoryRecord = {
        ...baseRecord,
        verificationStatus: 'UNVERIFIED_PROPOSAL'
      };

      const matchVerified = evaluateIncidentSimilarity(query, verifiedRecord);
      const matchRegressed = evaluateIncidentSimilarity(query, regressedRecord);
      const matchProposal = evaluateIncidentSimilarity(query, proposalRecord);

      assert.ok(matchVerified !== null);
      assert.ok(matchRegressed !== null);
      assert.ok(matchProposal !== null);

      // Similarity score must NOT change because an incident has a better resolution status!
      assert.equal(matchVerified.similarity.overallScore, matchRegressed.similarity.overallScore);
      assert.equal(matchVerified.similarity.overallScore, matchProposal.similarity.overallScore);
      assert.equal(matchVerified.similarity.matchType, matchRegressed.similarity.matchType);
      assert.equal(matchVerified.similarity.matchType, matchProposal.similarity.matchType);

      // But the outcome report advisories MUST distinguish them!
      assert.equal(matchVerified.outcomeReport.recommendationAdvisory, 'PROVEN_FIX_AVAILABLE');
      assert.equal(matchRegressed.outcomeReport.recommendationAdvisory, 'REGRESSED_FIX_DO_NOT_REUSE');
      assert.equal(matchProposal.outcomeReport.recommendationAdvisory, 'UNVERIFIED_PROPOSAL_ONLY');
      assert.equal(matchRegressed.outcomeReport.doNotReuseAsProvenFix, true);
      assert.equal(matchVerified.outcomeReport.doNotReuseAsProvenFix, false);
    });
  });
});
