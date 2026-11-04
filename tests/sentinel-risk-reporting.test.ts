import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { existsSync, unlinkSync } from 'node:fs';

import { parseStackTrace } from '../src/sentinel/analyzer/stack-trace-parser.js';
import { classifyIncident } from '../src/sentinel/analyzer/incident-classifier.js';
import { assessImpact } from '../src/sentinel/analyzer/impact-assessor.js';
import { evaluateRisk } from '../src/sentinel/analyzer/risk-evaluator.js';
import { buildInvestigationReport } from '../src/sentinel/analyzer/investigation-reporter.js';
import { SentinelAgent } from '../src/sentinel/sentinel-agent.js';
import { ChallengeTracker } from '../src/approval/challenge-tracker.js';
import { AuditLogger } from '../src/audit/audit-logger.js';
import { RiskReportSchema } from '../src/types/risk-report.js';

describe('Sentinel Intelligence Engine — Sub-Stage 4.2 Risk Evaluation & Reporting', () => {
  let auditLogPath: string;
  let auditLogger: AuditLogger;
  let challengeFile: string;
  let challengeTracker: ChallengeTracker;
  let sentinel: SentinelAgent;

  beforeEach(async () => {
    auditLogPath = join(tmpdir(), `audit-substage42-${randomUUID()}.jsonl`);
    auditLogger = new AuditLogger({
      filePath: auditLogPath,
      secretKey: 'devpulse-test-secret-at-least-32-chars-long'
    });
    await auditLogger.init();

    challengeFile = join(tmpdir(), `challenge-substage42-${randomUUID()}.jsonl`);
    challengeTracker = new ChallengeTracker({ persistenceFilePath: challengeFile });
    await challengeTracker.init();

    sentinel = new SentinelAgent({
      agentId: 'agn_sentinel_risk',
      runnerAgentId: 'agn_runner_risk',
      maintainerAllowlist: ['usr_lead'],
      challengeTracker,
      auditLogger
    });
  });

  afterEach(() => {
    if (existsSync(auditLogPath)) {
      try { unlinkSync(auditLogPath); } catch {}
    }
    if (existsSync(challengeFile)) {
      try { unlinkSync(challengeFile); } catch {}
    }
  });

  // =========================================================================
  // 1. DETERMINISTIC RISK SCORING & EXACT FORMULA
  // =========================================================================
  describe('1. Deterministic Risk Scoring Formula & Boundaries', () => {
    it('produces strictly identical scores for identical inputs (exact determinism)', () => {
      const input = '500 Internal Server Error in service=checkout-api: unhandled exception in src/checkout.ts:30';
      const parsed = parseStackTrace(input);
      const classif = classifyIncident(input, parsed);
      const impact = assessImpact(input, parsed, classif);

      const run1 = evaluateRisk(input, classif, parsed, impact);
      const run2 = evaluateRisk(input, classif, parsed, impact);

      assert.equal(run1.riskScore, run2.riskScore);
      assert.equal(run1.riskLevel, run2.riskLevel);
      assert.equal(run1.baseScore, run2.baseScore);
      assert.deepEqual(run1.appliedModifiers, run2.appliedModifiers);
    });

    it('applies exact base scores per incident category', () => {
      // 1. Production Alert: Base 65
      const alertInput = 'Production alert: latency spike';
      const p1 = parseStackTrace(alertInput);
      const c1 = classifyIncident(alertInput, p1);
      const r1 = evaluateRisk(alertInput, c1, p1, assessImpact(alertInput, p1, c1));
      assert.equal(r1.baseScore, 65);

      // 2. Runtime Exception: Base 40
      const exInput = 'TypeError: Cannot read properties of null';
      const p2 = parseStackTrace(exInput);
      const c2 = classifyIncident(exInput, p2);
      const r2 = evaluateRisk(exInput, c2, p2, assessImpact(exInput, p2, c2));
      assert.equal(r2.baseScore, 40);

      // 3. Test Failure: Base 20
      const testInput = 'AssertionError: expected true';
      const p3 = parseStackTrace(testInput);
      const c3 = classifyIncident(testInput, p3);
      const r3 = evaluateRisk(testInput, c3, p3, assessImpact(testInput, p3, c3));
      assert.equal(r3.baseScore, 20);

      // 4. Build Failure: Base 15
      const buildInput = 'src/app.ts:1:1 - error TS2322: Type mismatch';
      const p4 = parseStackTrace(buildInput);
      const c4 = classifyIncident(buildInput, p4);
      const r4 = evaluateRisk(buildInput, c4, p4, assessImpact(buildInput, p4, c4));
      assert.equal(r4.baseScore, 15);

      // 5. Unrecognized: Base 10
      const unrecInput = 'Generic note';
      const p5 = parseStackTrace(unrecInput);
      const c5 = classifyIncident(unrecInput, p5);
      const r5 = evaluateRisk(unrecInput, c5, p5, assessImpact(unrecInput, p5, c5));
      assert.equal(r5.baseScore, 10);
    });

    it('does NOT increase risk based on filenames alone', () => {
      // File has "auth" and "payment" in path, but error is a harmless local test typo
      const testLog = [
        'AssertionError: Expected 200 to be 200',
        '    at Context.<anonymous> (src/payment/auth_test.ts:40:10)'
      ].join('\n');

      const parsed = parseStackTrace(testLog);
      const classif = classifyIncident(testLog, parsed);
      const impact = assessImpact(testLog, parsed, classif);
      const result = evaluateRisk(testLog, classif, parsed, impact);

      // Must NOT apply security or outage modifiers based on "auth" or "payment" in filename
      const hasFilenameModifier = result.appliedModifiers.some((m) =>
        m.name.includes('FILENAME') || m.evidenceSource.includes('src/payment/auth_test.ts')
      );
      assert.equal(hasFilenameModifier, false);

      // Score: Base 20 - 10 (pre-production isolation) = 10 (LOW)
      assert.equal(result.riskScore, 10);
      assert.equal(result.riskLevel, 'LOW');
    });

    it('enforces score boundaries and clamps within [0, 100]', () => {
      // Max boundary test: Production Alert (65) + 500 Outage (+20) + Data Loss (+15) = 100 (CRITICAL)
      const criticalLog = 'Production alert: 500 Internal Server Error with corrupted data loss in live cluster';
      const pMax = parseStackTrace(criticalLog);
      const cMax = classifyIncident(criticalLog, pMax);
      const rMax = evaluateRisk(criticalLog, cMax, pMax, assessImpact(criticalLog, pMax, cMax));
      assert.equal(rMax.riskScore, 100);
      assert.equal(rMax.riskLevel, 'CRITICAL');

      // Validates against official RiskReportSchema
      assert.doesNotThrow(() => RiskReportSchema.parse(rMax.riskReport));
    });
  });

  // =========================================================================
  // 2. EVIDENCE-BASED IMPACT ASSESSMENT & BLAST RADIUS
  // =========================================================================
  describe('2. Evidence-Based Impact Assessment & Blast Radius', () => {
    it('marks blast radius as UNKNOWN when evidence is insufficient, preserving RiskReportSchema compatibility', () => {
      const vagueLog = 'Unexpected system glitch';
      const parsed = parseStackTrace(vagueLog);
      const classif = classifyIncident(vagueLog, parsed);
      const impact = assessImpact(vagueLog, parsed, classif);
      const risk = evaluateRisk(vagueLog, classif, parsed, impact);

      assert.equal(impact.classification, 'UNKNOWN');
      assert.deepEqual(impact.affectedComponents, ['UNKNOWN']);
      assert.deepEqual(risk.riskReport.blastRadius, ['UNKNOWN']);

      // Verifies strict schema validation: blastRadius is array of strings with min(1)
      const validated = RiskReportSchema.safeParse(risk.riskReport);
      assert.equal(validated.success, true);
    });

    it('classifies blast radius as ESTIMATED when multiple stack frames exist without service corroboration', () => {
      const log = [
        'TypeError: cannot read property of undefined',
        '    at render (src/components/button.ts:15:3)',
        '    at layout (src/layout/grid.ts:40:12)',
        '    at page (src/views/home.ts:10:5)'
      ].join('\n');

      const parsed = parseStackTrace(log);
      const classif = classifyIncident(log, parsed);
      const impact = assessImpact(log, parsed, classif);

      // Multiple stack frames do NOT prove downstream service impact
      assert.equal(impact.classification, 'ESTIMATED');
      assert.deepEqual(impact.affectedComponents, ['src/components/button.ts']);
      assert.ok(impact.unverifiedAssumptions.some((a) => a.includes('Multiple stack frames do not confirm downstream service degradation')));
    });

    it('classifies blast radius as KNOWN only when explicit service token and observed failure are corroborated', () => {
      const log = [
        '500 Internal Server Error in service=payment-gateway',
        '    at executeCharge (src/gateway.ts:25:9)'
      ].join('\n');

      const parsed = parseStackTrace(log);
      const classif = classifyIncident(log, parsed);
      const impact = assessImpact(log, parsed, classif);

      assert.equal(impact.classification, 'KNOWN');
      assert.deepEqual(impact.affectedComponents, ['src/gateway.ts']);
      assert.deepEqual(impact.affectedServices, ['payment-gateway']);
      assert.deepEqual(impact.observedFailures, ['500 Internal Server Error']);
    });
  });

  // =========================================================================
  // 3. CONFIDENCE AND RISK SEPARATION
  // =========================================================================
  describe('3. Diagnostic Confidence and Operational Risk Independence', () => {
    it('demonstrates High-Risk with Low Diagnostic Confidence', () => {
      // 1-line production alert with 500 error but NO stack trace
      const log = 'CRITICAL ALERT: 503 Service Unavailable during cluster down';
      const parsed = parseStackTrace(log);
      const classif = classifyIncident(log, parsed);
      const impact = assessImpact(log, parsed, classif);
      const risk = evaluateRisk(log, classif, parsed, impact);

      // High Risk: Base 65 + Outage (+20) = 85 (CRITICAL)
      assert.equal(risk.riskScore, 85);
      assert.equal(risk.riskLevel, 'CRITICAL');

      // Low Diagnostic Confidence: Insufficient evidence (no stack trace, no culprit line)
      assert.equal(classif.evidenceCompleteness, 'INSUFFICIENT');
    });

    it('demonstrates Low-Risk with High Diagnostic Confidence', () => {
      // Complete stack trace for an isolated pre-production TypeScript compiler error
      const log = 'src/utils/math.ts:10:5 - error TS2322: Type "number" is not assignable to type "string".';
      const parsed = parseStackTrace(log);
      const classif = classifyIncident(log, parsed);
      const impact = assessImpact(log, parsed, classif);
      const risk = evaluateRisk(log, classif, parsed, impact);

      // Low Risk: Base 15 - 10 (pre-production isolation) = 5 (LOW)
      assert.equal(risk.riskScore, 5);
      assert.equal(risk.riskLevel, 'LOW');

      // High Diagnostic Confidence: Complete evidence with exact file, line, and column
      assert.equal(classif.evidenceCompleteness, 'COMPLETE');
    });
  });

  // =========================================================================
  // 4. STRUCTURED REPORT & SWITCH ROOM MARKDOWN (NO AUTOMATIC CHALLENGE)
  // =========================================================================
  describe('4. Investigation Reporting & Switch Room Presentation', () => {
    it('builds structured markdown report with all required sections and NO automated approval challenge', () => {
      const rawText = [
        'TypeError: Cannot read properties of undefined (reading "token")',
        '    at AuthHandler.verify (src/auth/handler.ts:45:12)'
      ].join('\n');

      const parsed = parseStackTrace(rawText);
      const classif = classifyIncident(rawText, parsed);
      const impact = assessImpact(rawText, parsed, classif);
      const risk = evaluateRisk(rawText, classif, parsed, impact);

      const report = buildInvestigationReport({
        incidentId: 'INC-TEST-001',
        timestamp: new Date().toISOString(),
        classification: classif,
        diagnosis: {
          incidentCategory: classif.category,
          evidenceCompleteness: classif.evidenceCompleteness,
          rawErrorSignature: rawText,
          errorType: parsed.errorType,
          errorMessage: parsed.errorMessage,
          candidateCulpritFrame: parsed.candidateCulpritFrame,
          stackFrames: parsed.frames,
          findings: [],
          confirmedFacts: ['Execution halted in project source at candidate location src/auth/handler.ts:45'],
          hypotheses: ['Uncaught null or undefined dereference accessing "token"'],
          diagnosticConfidence: 0.9,
          unresolvedQuestions: [],
          limitations: []
        },
        riskEvaluation: risk,
        impact
      });

      assert.ok(report.formattedMarkdown.includes('### 🔍 [SENTINEL INVESTIGATION REPORT]'));
      assert.ok(report.formattedMarkdown.includes('Confirmed Facts'));
      assert.ok(report.formattedMarkdown.includes('Root-Cause Hypotheses'));
      assert.ok(report.formattedMarkdown.includes('Candidate Culprit Location'));
      assert.ok(report.formattedMarkdown.includes('Impact Assessment'));
      assert.ok(report.formattedMarkdown.includes('Diagnostic Confidence'));
      assert.ok(report.formattedMarkdown.includes('Operational Risk'));
      assert.ok(report.formattedMarkdown.includes('Recommended Next Investigative Steps'));

      // Strictly verifies NO approval challenge was created
      assert.equal(report.formattedMarkdown.includes('@devpulse approve'), false);
      assert.ok(report.formattedMarkdown.includes('No approval challenge or patch was automatically generated'));
    });
  });

  // =========================================================================
  // 5. AUDIT LOGGING OF INVESTIGATION OUTCOMES
  // =========================================================================
  describe('5. Append-Only Tamper-Evident Audit Logging', () => {
    it('records investigation outcomes and evidence provenance into audit log without challenge creation', async () => {
      const rawLog = [
        '500 Internal Server Error in service=billing-api',
        '    at chargeUser (src/billing.ts:80:10)'
      ].join('\n');

      const report = await sentinel.generateInvestigationReport({
        rawText: rawLog,
        incidentId: 'INC-AUDIT-999',
        roomId: 'room_devpulse_ops'
      });

      assert.equal(report.incidentId, 'INC-AUDIT-999');
      assert.equal(report.impact.affectedServices[0], 'billing-api');

      // Verify audit logger recorded the entry
      const { entries: auditEntries } = await auditLogger.getEntries();
      const investigationEntry = auditEntries.find((e) => e.action === 'INVESTIGATION_REPORTED');

      assert.ok(investigationEntry, 'Audit entry INVESTIGATION_REPORTED must exist');
      assert.equal(investigationEntry?.incidentId, 'INC-AUDIT-999');
      assert.equal(investigationEntry?.actor.type, 'SENTINEL');
      assert.equal((investigationEntry?.payload as any).riskScore, report.riskEvaluation.riskScore);
      assert.equal((investigationEntry?.payload as any).blastRadius, report.impact.classification);

      // Verify challenge tracker was NOT touched (zero challenges created)
      assert.equal((challengeTracker as any).challenges.size, 0);
    });
  });
});
