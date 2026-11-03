import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  IncidentRecordSchema,
  RiskReportSchema,
  calculateRiskLevel,
  RemediationSpecSchema
} from '../src/types/index.js';

describe('Domain Models & Schemas', () => {
  describe('IncidentRecordSchema', () => {
    it('successfully parses a valid incident record', () => {
      const valid = {
        id: 'INC-20261103-01',
        timestamp: '2026-11-03T18:00:00.000Z',
        errorSignature: 'TypeError: Cannot read properties of undefined',
        affectedTarget: 'src/auth/jwt.ts:42',
        rootCause: 'Missing null check on optional token object',
        fixSummary: 'Added optional chaining and fallback',
        diffHash: 'a'.repeat(64),
        prLink: 'https://github.com/org/repo/pull/12',
        outcome: 'RESOLVED',
        metadata: { severity: 'high' }
      };

      const result = IncidentRecordSchema.parse(valid);
      assert.equal(result.id, 'INC-20261103-01');
      assert.equal(result.outcome, 'RESOLVED');
      assert.equal(result.diffHash, 'a'.repeat(64));
    });

    it('rejects an invalid diffHash format', () => {
      const invalid = {
        id: 'INC-01',
        timestamp: '2026-11-03T18:00:00.000Z',
        errorSignature: 'Error',
        affectedTarget: 'src/main.ts',
        rootCause: 'Root cause',
        fixSummary: 'Fixed',
        diffHash: 'short-non-hex-hash',
        prLink: '#1',
        outcome: 'RESOLVED'
      };

      assert.throws(() => IncidentRecordSchema.parse(invalid), /diffHash must be a 64-character/);
    });

    it('rejects invalid outcomes', () => {
      const invalid = {
        id: 'INC-01',
        timestamp: '2026-11-03T18:00:00.000Z',
        errorSignature: 'Error',
        affectedTarget: 'src/main.ts',
        rootCause: 'Root cause',
        fixSummary: 'Fixed',
        diffHash: 'b'.repeat(64),
        prLink: '#1',
        outcome: 'UNKNOWN_OUTCOME'
      };

      assert.throws(() => IncidentRecordSchema.parse(invalid));
    });
  });

  describe('RiskReportSchema', () => {
    it('successfully parses a valid risk report and evaluates risk level', () => {
      const valid = {
        riskScore: 18,
        riskLevel: calculateRiskLevel(18),
        blastRadius: ['src/auth/jwt.ts'],
        testsImpacted: ['auth-suite'],
        rollbackStrategy: 'Revert git commit; zero migration dependencies',
        complianceNotes: 'GDPR compliant',
        safetyGuarantees: ['Backward compatible API', 'Non-breaking schema']
      };

      const parsed = RiskReportSchema.parse(valid);
      assert.equal(parsed.riskScore, 18);
      assert.equal(parsed.riskLevel, 'LOW');
      assert.equal(parsed.blastRadius.length, 1);
    });

    it('enforces score boundaries between 0 and 100', () => {
      assert.throws(() => {
        RiskReportSchema.parse({
          riskScore: 150,
          riskLevel: 'CRITICAL',
          blastRadius: ['src/index.ts'],
          testsImpacted: [],
          rollbackStrategy: 'Revert',
          safetyGuarantees: []
        });
      }, /Risk score cannot exceed 100/);

      assert.throws(() => {
        RiskReportSchema.parse({
          riskScore: -5,
          riskLevel: 'LOW',
          blastRadius: ['src/index.ts'],
          testsImpacted: [],
          rollbackStrategy: 'Revert',
          safetyGuarantees: []
        });
      }, /Risk score cannot be below 0/);
    });

    it('maps risk levels correctly according to score thresholds', () => {
      assert.equal(calculateRiskLevel(10), 'LOW');
      assert.equal(calculateRiskLevel(35), 'MEDIUM');
      assert.equal(calculateRiskLevel(65), 'HIGH');
      assert.equal(calculateRiskLevel(95), 'CRITICAL');
    });
  });

  describe('RemediationSpecSchema', () => {
    it('validates a complete remediation specification', () => {
      const validSpec = {
        id: 'spec_20261103_01',
        incidentId: 'INC-20261103-01',
        createdAt: '2026-11-03T18:05:00.000Z',
        targetRepository: 'owner/devpulse-demo',
        baseBranch: 'main',
        targetBranch: 'devpulse/fix-token-lookup',
        errorSignature: 'TypeError: Cannot read properties of undefined',
        rootCause: 'Missing null check on optional token',
        patches: [
          {
            path: 'src/auth.ts',
            action: 'MODIFY' as const,
            patchDiff: '@@ -10,2 +10,2 @@\n- return user.token;\n+ return user?.token ?? null;'
          }
        ],
        diffHash: 'c'.repeat(64),
        riskReport: {
          riskScore: 12,
          riskLevel: 'LOW' as const,
          blastRadius: ['src/auth.ts'],
          testsImpacted: ['test/auth.test.ts'],
          rollbackStrategy: 'Revert single commit',
          safetyGuarantees: ['Zero downtime']
        },
        verificationCommands: ['npm test'],
        status: 'PROPOSED' as const
      };

      const parsed = RemediationSpecSchema.parse(validSpec);
      assert.equal(parsed.id, 'spec_20261103_01');
      assert.equal(parsed.status, 'PROPOSED');
      assert.equal(parsed.patches.length, 1);
    });
  });
});

