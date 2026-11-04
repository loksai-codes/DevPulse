import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import { SentinelAgent } from '../src/sentinel/sentinel-agent.js';
import { ChallengeTracker } from '../src/approval/challenge-tracker.js';
import { IncidentStore } from '../src/memory/incident-store.js';
import { IncidentMemoryRecord, IncidentMemoryQuery } from '../src/memory/types.js';
import {
  evaluateIncidentSimilarity,
  rankHistoricalMatches,
  SIMILARITY_WEIGHTS
} from '../src/memory/similarity-engine.js';

describe('Sentinel-Memory Integration (Read-Only Contextual Advisory)', () => {
  const sampleTrace = [
    'Error: TokenExpiredError: jwt expired at verifyToken',
    '    at verifyToken (src/auth/jwt.ts:24:12)',
    '    at authenticate (src/auth/session.ts:50:5)',
    '    at handleRequest (src/server.ts:88:9)'
  ].join('\n');

  const createBaseRecord = (id: string, overrides: Partial<IncidentMemoryRecord> = {}): IncidentMemoryRecord => ({
    id,
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
    resolutionHistory: [],
    ...overrides
  });

  const setupStore = async (dirName: string, records: IncidentMemoryRecord[]): Promise<{ store: IncidentStore; cleanup: () => Promise<void> }> => {
    const tempDir = path.resolve(`./temp_test_${dirName}_${Date.now()}`);
    await fs.mkdir(tempDir, { recursive: true });
    const jsonlPath = path.join(tempDir, 'incidents.jsonl');
    const mdPath = path.join(tempDir, 'incidents.md');
    const quarPath = path.join(tempDir, 'incidents.quarantine.jsonl');

    const store = new IncidentStore({ jsonlPath, markdownPath: mdPath, quarantinePath: quarPath });
    await store.init();
    for (const r of records) {
      await store.append(r);
    }

    const cleanup = async () => {
      await fs.rm(tempDir, { recursive: true, force: true });
    };

    return { store, cleanup };
  };

  const createSentinel = (store?: IncidentStore) => {
    const challengeTracker = new ChallengeTracker();
    return new SentinelAgent({
      agentId: 'sentinel-01',
      runnerAgentId: 'runner-01',
      maintainerAllowlist: ['alice', 'bob'],
      challengeTracker,
      incidentStore: store
    });
  };

  describe('1. Verified Precedent (VERIFIED_RESOLVED)', () => {
    it('integrates verified precedent with match score, PR link, and PROVEN_FIX_AVAILABLE advisory', async () => {
      const verifiedRecord = createBaseRecord('INC-2026-VERIFIED', {
        verificationStatus: 'VERIFIED_RESOLVED',
        resolutionHistory: [
          {
            id: 'evt_01',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:15:00.000Z',
            evidence: 'Verified resolution merged in PR #101 with 15 passing tests. source: CI_CD_PIPELINE INDEPENDENTLY_VERIFIED [evidenceHash: ' + '1'.repeat(64) + ']',
            actor: { type: 'SYSTEM', id: 'ci_runner', name: 'CI Pipeline' }
          }
        ]
      });

      const { store, cleanup } = await setupStore('verified_precedent', [verifiedRecord]);
      try {
        const sentinel = createSentinel(store);
        const report = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        assert.equal(report.historicalPrecedents.length, 1);
        const precedent = report.historicalPrecedents[0]!;
        assert.equal(precedent.incidentId, 'INC-2026-VERIFIED');
        assert.equal(precedent.matchType, 'EXACT');
        assert.ok(precedent.overallScore >= 0.80);
        assert.equal(precedent.historicalOutcome.currentStatus, 'VERIFIED_RESOLVED');
        assert.equal(precedent.historicalOutcome.recommendationAdvisory, 'PROVEN_FIX_AVAILABLE');
        assert.equal(precedent.historicalOutcome.doNotReuseAsProvenFix, false);
        assert.ok(precedent.historicalOutcome.prLink.includes('pull/101'));

        assert.ok(report.formattedMarkdown.includes('### 🔍 [SENTINEL INVESTIGATION REPORT]'));
        assert.ok(report.formattedMarkdown.includes('#### 📚 Historical Precedents & Outcome Intelligence'));
        assert.ok(report.formattedMarkdown.includes('INC-2026-VERIFIED'));
        assert.ok(report.formattedMarkdown.includes('Prior Root Cause:'));
        assert.ok(!report.formattedMarkdown.includes('CRITICAL WARNING'));
      } finally {
        await cleanup();
      }
    });
  });

  describe('2. Currently Regressed Precedent (REGRESSED)', () => {
    it('prominently flags currently regressed precedent with REGRESSED_FIX_DO_NOT_REUSE and critical warning', async () => {
      const regressedRecord = createBaseRecord('INC-2026-REGRESSED', {
        verificationStatus: 'REGRESSED',
        outcome: 'REGRESSED',
        resolutionHistory: [
          {
            id: 'evt_01',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:00:00.000Z',
            evidence: 'Initial fix [evidenceHash: ' + '1'.repeat(64) + ']'
          },
          {
            id: 'evt_02',
            fromStatus: 'VERIFIED_RESOLVED',
            toStatus: 'REGRESSED',
            timestamp: '2026-11-04T12:20:00.000Z',
            evidence: 'TokenExpiredError reappeared under high concurrency in production [evidenceHash: ' + '2'.repeat(64) + ']'
          }
        ]
      });

      const { store, cleanup } = await setupStore('regressed_precedent', [regressedRecord]);
      try {
        const sentinel = createSentinel(store);
        const report = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        assert.equal(report.historicalPrecedents.length, 1);
        const precedent = report.historicalPrecedents[0]!;
        assert.equal(precedent.incidentId, 'INC-2026-REGRESSED');
        assert.equal(precedent.historicalOutcome.currentStatus, 'REGRESSED');
        assert.equal(precedent.historicalOutcome.isRegressed, true);
        assert.equal(precedent.historicalOutcome.doNotReuseAsProvenFix, true);
        assert.equal(precedent.historicalOutcome.recommendationAdvisory, 'REGRESSED_FIX_DO_NOT_REUSE');

        assert.ok(report.formattedMarkdown.includes('CRITICAL WARNING'));
        assert.ok(report.formattedMarkdown.includes('Do NOT reuse as a proven fix'));
      } finally {
        await cleanup();
      }
    });
  });

  describe('3. Recovered Precedent with Historical Regression', () => {
    it('presents recovered precedent as VERIFIED_RESOLVED while prominently disclosing previous regression', async () => {
      const recoveredRecord = createBaseRecord('INC-2026-RECOVERED', {
        verificationStatus: 'VERIFIED_RESOLVED',
        outcome: 'RESOLVED',
        resolutionHistory: [
          {
            id: 'evt_01',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:00:00.000Z',
            evidence: 'Initial fix [evidenceHash: ' + '1'.repeat(64) + ']'
          },
          {
            id: 'evt_02',
            fromStatus: 'VERIFIED_RESOLVED',
            toStatus: 'REGRESSED',
            timestamp: '2026-11-04T12:10:00.000Z',
            evidence: 'Regression observed [evidenceHash: ' + '2'.repeat(64) + ']'
          },
          {
            id: 'evt_03',
            fromStatus: 'REGRESSED',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: '2026-11-04T12:30:00.000Z',
            evidence: 'Verified resolution merged in PR #108 with 22 passing tests with fresh commit [evidenceHash: ' + '3'.repeat(64) + ']'
          }
        ]
      });

      const { store, cleanup } = await setupStore('recovered_precedent', [recoveredRecord]);
      try {
        const sentinel = createSentinel(store);
        const report = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        assert.equal(report.historicalPrecedents.length, 1);
        const precedent = report.historicalPrecedents[0]!;
        assert.equal(precedent.incidentId, 'INC-2026-RECOVERED');
        assert.equal(precedent.historicalOutcome.currentStatus, 'VERIFIED_RESOLVED');
        assert.equal(precedent.historicalOutcome.classification, 'VERIFIED_RESOLVED');
        assert.equal(precedent.historicalOutcome.isRegressed, false);
        assert.equal(precedent.historicalOutcome.hasHistoricalRegression, true);
        assert.equal(precedent.historicalOutcome.doNotReuseAsProvenFix, false);
        assert.equal(precedent.historicalOutcome.recommendationAdvisory, 'PROVEN_FIX_AVAILABLE');

        assert.ok(report.formattedMarkdown.includes('HISTORICAL REGRESSION WARNING'));
        assert.ok(report.formattedMarkdown.includes('prior regression in its lifecycle before resolution was verified with fresh evidence'));
        assert.ok(!report.formattedMarkdown.includes('This historical resolution subsequently **REGRESSED** in production'));
      } finally {
        await cleanup();
      }
    });
  });

  describe('4. Partial Mitigation Precedent (PARTIAL_RESOLUTION)', () => {
    it('flags partial resolution as partial mitigation with defect disclosures', async () => {
      const partialRecord = createBaseRecord('INC-2026-PARTIAL', {
        verificationStatus: 'PARTIAL_RESOLUTION',
        outcome: 'PARTIAL',
        resolutionHistory: [
          {
            id: 'evt_01',
            toStatus: 'PARTIAL_RESOLUTION',
            timestamp: '2026-11-04T12:10:00.000Z',
            evidence: 'Temporary mitigation applied source: USER_ASSERTION [evidenceHash: ' + '4'.repeat(64) + ']',
            actor: { type: 'HUMAN', id: 'alice', name: 'Alice Operator' }
          }
        ]
      });

      const { store, cleanup } = await setupStore('partial_precedent', [partialRecord]);
      try {
        const sentinel = createSentinel(store);
        const report = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        assert.equal(report.historicalPrecedents.length, 1);
        const precedent = report.historicalPrecedents[0]!;
        assert.equal(precedent.historicalOutcome.currentStatus, 'PARTIAL_RESOLUTION');
        assert.equal(precedent.historicalOutcome.recommendationAdvisory, 'PARTIAL_MITIGATION_ONLY');

        assert.ok(report.formattedMarkdown.includes('PARTIAL MITIGATION ONLY'));
      } finally {
        await cleanup();
      }
    });
  });

  describe('5. Unverified Proposal Precedent (UNVERIFIED_PROPOSAL)', () => {
    it('flags unverified proposal as UNVERIFIED_PROPOSAL_ONLY and never describes as proven', async () => {
      const proposalRecord = createBaseRecord('INC-2026-PROPOSAL', {
        verificationStatus: 'UNVERIFIED_PROPOSAL',
        outcome: 'CLOSED_WITHOUT_MERGE',
        resolutionHistory: []
      });

      const { store, cleanup } = await setupStore('proposal_precedent', [proposalRecord]);
      try {
        const sentinel = createSentinel(store);
        const report = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        assert.equal(report.historicalPrecedents.length, 1);
        const precedent = report.historicalPrecedents[0]!;
        assert.equal(precedent.historicalOutcome.currentStatus, 'UNVERIFIED_PROPOSAL');
        assert.equal(precedent.historicalOutcome.recommendationAdvisory, 'UNVERIFIED_PROPOSAL_ONLY');

        assert.ok(report.formattedMarkdown.includes('UNVERIFIED PROPOSAL'));
      } finally {
        await cleanup();
      }
    });
  });

  describe('6. Diagnostic Confidence & Risk Invariance', () => {
    it('proves diagnosticConfidence and riskScore are 100% mathematically identical with and without historical matches', async () => {
      const verifiedRecord = createBaseRecord('INC-2026-VERIFIED');
      const { store, cleanup } = await setupStore('invariance', [verifiedRecord]);

      try {
        // Run Sentinel without memory store
        const sentinelNoMemory = createSentinel(undefined);
        const reportNoMemory = await sentinelNoMemory.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        // Run Sentinel with memory store containing exact verified match
        const sentinelWithMemory = createSentinel(store);
        const reportWithMemory = await sentinelWithMemory.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        // Precedents differ
        assert.equal(reportNoMemory.historicalPrecedents.length, 0);
        assert.equal(reportWithMemory.historicalPrecedents.length, 1);

        // Invariance guarantees: Diagnostics must NOT be influenced by historical matches!
        assert.equal(reportNoMemory.diagnosis.diagnosticConfidence, reportWithMemory.diagnosis.diagnosticConfidence);
        assert.equal(reportNoMemory.riskEvaluation.riskScore, reportWithMemory.riskEvaluation.riskScore);
        assert.equal(reportNoMemory.riskEvaluation.riskLevel, reportWithMemory.riskEvaluation.riskLevel);
        assert.equal(reportNoMemory.riskEvaluation.baseScore, reportWithMemory.riskEvaluation.baseScore);
        assert.deepEqual(reportNoMemory.riskEvaluation.appliedModifiers, reportWithMemory.riskEvaluation.appliedModifiers);
        assert.equal(reportNoMemory.impact.classification, reportWithMemory.impact.classification);
        assert.deepEqual(reportNoMemory.impact.affectedComponents, reportWithMemory.impact.affectedComponents);
        assert.deepEqual(reportNoMemory.impact.affectedServices, reportWithMemory.impact.affectedServices);
        assert.deepEqual(reportNoMemory.impact.observedFailures, reportWithMemory.impact.observedFailures);
        assert.equal(reportNoMemory.impact.evidenceSummary, reportWithMemory.impact.evidenceSummary);
        assert.deepEqual(reportNoMemory.diagnosis.confirmedFacts, reportWithMemory.diagnosis.confirmedFacts);
        assert.deepEqual(reportNoMemory.diagnosis.hypotheses, reportWithMemory.diagnosis.hypotheses);
        assert.equal(reportNoMemory.diagnosis.candidateCulpritFrame?.file, reportWithMemory.diagnosis.candidateCulpritFrame?.file);
        assert.deepEqual(reportNoMemory.diagnosis.unresolvedQuestions, reportWithMemory.diagnosis.unresolvedQuestions);
        assert.deepEqual(reportNoMemory.diagnosis.limitations, reportWithMemory.diagnosis.limitations);
        assert.equal(reportNoMemory.classification.category, reportWithMemory.classification.category);
        assert.equal(reportNoMemory.classification.evidenceCompleteness, reportWithMemory.classification.evidenceCompleteness);
        assert.deepEqual(reportNoMemory.nextSteps, reportWithMemory.nextSteps);

        // Also test investigate() Remediationspec invariance with and without memory
        const invNoMemory = await sentinelNoMemory.investigate({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core',
          senderId: 'alice',
          roomId: 'room_1'
        });

        const invWithMemory = await sentinelWithMemory.investigate({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core',
          senderId: 'alice',
          roomId: 'room_1'
        });

        // RemediationSpec parameters remain 100% identical!
        assert.deepEqual(invNoMemory.spec.patches, invWithMemory.spec.patches);
        assert.equal(invNoMemory.spec.diffHash, invWithMemory.spec.diffHash);
        assert.equal(invNoMemory.spec.rootCause, invWithMemory.spec.rootCause);
        assert.equal(invNoMemory.spec.targetRepository, invWithMemory.spec.targetRepository);
        assert.equal(invNoMemory.spec.baseBranch, invWithMemory.spec.baseBranch);
        assert.ok(/^devpulse\/fix-inc-\d{6}$/.test(invNoMemory.spec.targetBranch));
        assert.ok(/^devpulse\/fix-inc-\d{6}$/.test(invWithMemory.spec.targetBranch));
        assert.deepEqual(invNoMemory.spec.verificationCommands, invWithMemory.spec.verificationCommands);
        assert.equal(invNoMemory.riskReport.riskScore, invWithMemory.riskReport.riskScore);
        assert.equal(invNoMemory.riskReport.riskLevel, invWithMemory.riskReport.riskLevel);
        assert.deepEqual(invNoMemory.riskReport.blastRadius, invWithMemory.riskReport.blastRadius);
      } finally {
        await cleanup();
      }
    });
  });

  describe('7. Remediation Independence', () => {
    it('proves investigation proposal patches in investigate() are independent and not copied from historical diffs', async () => {
      const historicalRecordWithSpecialFix = createBaseRecord('INC-2026-SPECIAL', {
        fixSummary: 'Complex custom crypto salt rotation fix',
        diffHash: 'f'.repeat(64)
      });

      const { store, cleanup } = await setupStore('remediation_independence', [historicalRecordWithSpecialFix]);
      try {
        const sentinel = createSentinel(store);
        const result = await sentinel.investigate({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core',
          senderId: 'alice',
          roomId: 'room_sec'
        });

        // Remediation proposal must be generated strictly from current trace, NOT copied from history
        assert.ok(result.spec.patches.length > 0);
        assert.notEqual(result.spec.diffHash, historicalRecordWithSpecialFix.diffHash);
        assert.notEqual(result.spec.fixSummary, historicalRecordWithSpecialFix.fixSummary);
        assert.ok(result.formattedRoomMessage.includes('Historical Precedents'));
      } finally {
        await cleanup();
      }
    });
  });

  describe('8. Repository Boundary Isolation', () => {
    it('strictly isolates memory by repository (records in devpulse/runner never match devpulse/core query)', async () => {
      const runnerRecord = createBaseRecord('INC-2026-RUNNER', {
        canonicalRepository: 'devpulse/runner' // Different repository
      });

      const { store, cleanup } = await setupStore('repo_isolation', [runnerRecord]);
      try {
        const sentinel = createSentinel(store);
        const report = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core' // Target repository
        });

        // Cross-repository record must NEVER be returned
        assert.equal(report.historicalPrecedents.length, 0);
        assert.ok(report.formattedMarkdown.includes('*(No similar historical incidents found in repository memory)*'));
      } finally {
        await cleanup();
      }
    });
  });

  describe('9. Missing or Invalid Repository Identity', () => {
    it('safely skips memory lookup with notice when canonicalRepository is missing or invalid', async () => {
      const record = createBaseRecord('INC-2026-TEST');
      const { store, cleanup } = await setupStore('repo_missing', [record]);
      try {
        const sentinel = createSentinel(store);

        // Case A: Missing repository identity
        const reportMissing = await sentinel.generateInvestigationReport({
          rawText: sampleTrace
          // canonicalRepository omitted
        });
        assert.equal(reportMissing.historicalPrecedents.length, 0);
        assert.ok(reportMissing.historicalPrecedentsNotice);
        assert.ok(reportMissing.historicalPrecedentsNotice.includes('Repository identity unavailable'));
        assert.ok(reportMissing.formattedMarkdown.includes('Repository identity unavailable'));

        // Case B: Invalid path traversal repository identity
        const reportInvalid = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: '../../etc/passwd'
        });
        assert.equal(reportInvalid.historicalPrecedents.length, 0);
        assert.ok(reportInvalid.historicalPrecedentsNotice);
        assert.ok(reportInvalid.historicalPrecedentsNotice.includes('Invalid repository identity'));
        assert.ok(reportInvalid.formattedMarkdown.includes('Invalid repository identity'));
      } finally {
        await cleanup();
      }
    });
  });

  describe('10. Store Unavailable or Retrieval Error Resilience', () => {
    it('gracefully degrades when incidentStore is omitted or encounters retrieval errors', async () => {
      // Case A: IncidentStore omitted (not configured)
      const sentinelNoStore = createSentinel(undefined);
      const reportNoStore = await sentinelNoStore.generateInvestigationReport({
        rawText: sampleTrace,
        canonicalRepository: 'devpulse/core'
      });
      assert.equal(reportNoStore.historicalPrecedents.length, 0);
      assert.ok(reportNoStore.historicalPrecedentsNotice?.includes('Memory store unavailable'));

      // Case B: IncidentStore throws an error during listByRepository
      const { store, cleanup } = await setupStore('error_resilience', []);
      try {
        // Monkeypatch listByRepository to simulate a disk I/O error
        const originalList = store.listByRepository.bind(store);
        store.listByRepository = () => {
          throw new Error('EIO: simulated disk I/O failure during memory lookup');
        };

        const sentinelFaulty = createSentinel(store);
        const reportFaulty = await sentinelFaulty.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        // Sentinel must NOT crash! Investigation report completes cleanly with notice
        assert.equal(reportFaulty.historicalPrecedents.length, 0);
        assert.ok(reportFaulty.historicalPrecedentsNotice?.includes('Historical memory query encountered an error'));
        assert.ok(reportFaulty.historicalPrecedentsNotice?.includes('EIO'));
        assert.ok(reportFaulty.formattedMarkdown.includes('Historical memory query encountered an error'));

        store.listByRepository = originalList;
      } finally {
        await cleanup();
      }
    });
  });

  describe('11. Read-Only Interaction Verification (Spies on IncidentStore)', () => {
    it('proves Sentinel invokes strictly read-only listByRepository and never calls write/transition/persistence methods', async () => {
      const record = createBaseRecord('INC-2026-SPY');
      const { store, cleanup } = await setupStore('spies', [record]);

      try {
        let listByRepoCalls = 0;
        const originalList = store.listByRepository.bind(store);
        store.listByRepository = (repo: string) => {
          listByRepoCalls++;
          return originalList(repo);
        };

        // Spy traps for write / mutation methods
        let forbiddenMethodCalled = false;
        let forbiddenMethodName = '';

        const trap = (name: string) => () => {
          forbiddenMethodCalled = true;
          forbiddenMethodName = name;
          throw new Error(`Forbidden method ${name} was invoked during read-only investigation!`);
        };

        store.append = trap('append') as unknown as typeof store.append;
        store.transitionResolutionStatus = trap('transitionResolutionStatus') as unknown as typeof store.transitionResolutionStatus;
        store.atomicRewriteJsonl = trap('atomicRewriteJsonl') as unknown as typeof store.atomicRewriteJsonl;
        store.rebuildMarkdown = trap('rebuildMarkdown') as unknown as typeof store.rebuildMarkdown;

        const sentinel = createSentinel(store);

        // Execute generateInvestigationReport
        const report = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        // Execute investigate
        const result = await sentinel.investigate({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core',
          senderId: 'alice',
          roomId: 'room_sec'
        });

        // Assertions:
        // 1. Read-only listByRepository was called
        assert.ok(listByRepoCalls >= 2);
        // 2. Precedent was returned
        assert.equal(report.historicalPrecedents.length, 1);
        assert.equal(result.historicalPrecedents?.length, 1);
        // 3. ZERO write or transition methods were called
        assert.equal(forbiddenMethodCalled, false, `Forbidden method ${forbiddenMethodName} was called`);
      } finally {
        await cleanup();
      }
    });
  });

  describe('12. Four Distinct Store Configuration & Initialization Lifecycle States', () => {
    it('Condition A: IncidentStore not configured (omitted) -> returns memory-unavailable notice', async () => {
      const sentinel = createSentinel(undefined);
      const report = await sentinel.generateInvestigationReport({
        rawText: sampleTrace,
        canonicalRepository: 'devpulse/core'
      });

      assert.equal(report.historicalPrecedents.length, 0);
      assert.equal(report.historicalPrecedentsNotice, 'Memory store unavailable: proceeding with log-grounded investigation.');
      assert.ok(report.formattedMarkdown.includes('Memory store unavailable: proceeding with log-grounded investigation.'));
    });

    it('Condition B: IncidentStore configured but not initialized -> returns memory-unavailable notice', async () => {
      const tempDir = path.resolve(`./temp_test_uninit_${Date.now()}`);
      const jsonlPath = path.join(tempDir, 'incidents.jsonl');
      const mdPath = path.join(tempDir, 'incidents.md');
      const quarPath = path.join(tempDir, 'incidents.quarantine.jsonl');

      // Create store instance WITHOUT calling store.init()
      const uninitStore = new IncidentStore({ jsonlPath, markdownPath: mdPath, quarantinePath: quarPath });

      try {
        const sentinel = createSentinel(uninitStore);
        const report = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        assert.equal(report.historicalPrecedents.length, 0);
        assert.equal(report.historicalPrecedentsNotice, 'Memory store unavailable: proceeding with log-grounded investigation.');
        assert.ok(report.formattedMarkdown.includes('Memory store unavailable: proceeding with log-grounded investigation.'));
      } finally {
        await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
      }
    });

    it('Condition C: Initialized store with zero incidents -> returns clean no-similar-incidents notice', async () => {
      const { store, cleanup } = await setupStore('empty_store', []);

      try {
        const sentinel = createSentinel(store);
        const report = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        assert.equal(report.historicalPrecedents.length, 0);
        assert.ok(!report.historicalPrecedentsNotice);
        assert.ok(report.formattedMarkdown.includes('*(No similar historical incidents found in repository memory)*'));
      } finally {
        await cleanup();
      }
    });

    it('Condition D: Initialized store with matching incidents -> shows historical precedents', async () => {
      const matchingRecord = createBaseRecord('INC-2026-MATCH');
      const { store, cleanup } = await setupStore('matching_store', [matchingRecord]);

      try {
        const sentinel = createSentinel(store);
        const report = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        assert.equal(report.historicalPrecedents.length, 1);
        assert.equal(report.historicalPrecedents[0]?.incidentId, 'INC-2026-MATCH');
        assert.ok(!report.historicalPrecedentsNotice);
        assert.ok(report.formattedMarkdown.includes('INC-2026-MATCH'));
        assert.ok(!report.formattedMarkdown.includes('*(No similar historical incidents found in repository memory)*'));
        assert.ok(!report.formattedMarkdown.includes('Memory store unavailable'));
      } finally {
        await cleanup();
      }
    });
  });

  describe('13. Similarity Scoring & Memory Engine Direct Equivalence', () => {
    it('preserves established weights: 0.45 signature, 0.35 target, 0.10 category, 0.10 stack frames', () => {
      assert.deepEqual(SIMILARITY_WEIGHTS, {
        SIGNATURE_OVERLAP: 0.45,
        TARGET_OVERLAP: 0.35,
        CATEGORY_OVERLAP: 0.10,
        FRAME_OVERLAP: 0.10
      });
    });

    it('compares Sentinel precedent results directly against evaluateIncidentSimilarity() and rankHistoricalMatches()', async () => {
      // 1. Exact match record (exact signature + exact target path)
      const exactRecord = createBaseRecord('INC-EXACT-001', {
        errorSignature: 'Error: TokenExpiredError: jwt expired at verifyToken',
        affectedTarget: 'src/auth/jwt.ts',
        category: 'RUNTIME_EXCEPTION'
      });

      // 2. Partial match record (same target path and category, different error tokens)
      const partialRecord = createBaseRecord('INC-PARTIAL-002', {
        errorSignature: 'Error: JsonWebTokenError: invalid signature at verifyToken',
        affectedTarget: 'src/auth/jwt.ts',
        category: 'RUNTIME_EXCEPTION'
      });

      // 3. Different repository record (must be excluded by repo boundary)
      const foreignRecord = createBaseRecord('INC-FOREIGN-003', {
        canonicalRepository: 'devpulse/other-repo',
        errorSignature: 'Error: TokenExpiredError: jwt expired at verifyToken',
        affectedTarget: 'src/auth/jwt.ts'
      });

      const { store, cleanup } = await setupStore('direct_engine_comp', [
        exactRecord,
        partialRecord,
        foreignRecord
      ]);

      try {
        const sentinel = createSentinel(store);
        const report = await sentinel.generateInvestigationReport({
          rawText: sampleTrace,
          canonicalRepository: 'devpulse/core'
        });

        // Independently evaluate using existing memory engine APIs directly
        const candidateRecords = store.listByRepository('devpulse/core');
        const firstLine = report.diagnosis.rawErrorSignature.split(/\r?\n/)[0]?.trim();
        const expectedErrorSig =
          report.diagnosis.errorType && report.diagnosis.errorMessage
            ? `${report.diagnosis.errorType}: ${report.diagnosis.errorMessage}`
            : firstLine || report.classification.summary;

        const directQuery: IncidentMemoryQuery = {
          canonicalRepository: 'devpulse/core',
          errorSignature: expectedErrorSig,
          category: report.classification.category,
          affectedTarget: report.diagnosis.candidateCulpritFrame?.file ?? report.impact.affectedComponents[0],
          stackFrames: report.diagnosis.stackFrames,
          minSimilarityScore: 0.60,
          maxResults: 3
        };

        const directMatches = candidateRecords
          .map((rec) => evaluateIncidentSimilarity(directQuery, rec))
          .filter((m): m is NonNullable<typeof m> => m !== null);

        const directRanked = rankHistoricalMatches(directMatches).slice(0, 3);

        // Assert exact equivalence between Sentinel's precedents and direct memory engine outputs
        assert.equal(report.historicalPrecedents.length, directRanked.length);

        for (let i = 0; i < directRanked.length; i++) {
          const sentinelPrecedent = report.historicalPrecedents[i]!;
          const engineMatch = directRanked[i]!;

          assert.equal(sentinelPrecedent.incidentId, engineMatch.record.id);
          assert.equal(sentinelPrecedent.overallScore, engineMatch.similarity.overallScore);
          assert.equal(sentinelPrecedent.matchType, engineMatch.similarity.matchType);
          assert.equal(sentinelPrecedent.relevanceExplanation, engineMatch.relevanceExplanation);
          assert.deepEqual(sentinelPrecedent.historicalOutcome, engineMatch.outcomeReport);
        }

        // Verify exact match classification is preserved on the top match
        assert.equal(report.historicalPrecedents[0]?.matchType, 'EXACT');
        assert.equal(report.historicalPrecedents[0]?.overallScore, directRanked[0]!.similarity.overallScore);
      } finally {
        await cleanup();
      }
    });
  });
});
