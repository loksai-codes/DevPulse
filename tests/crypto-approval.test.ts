import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  computeDiffHash,
  computeApprovalSignature,
  verifyApprovalIntegrity,
  normalizeText
} from '../src/utils/crypto.js';
import type { RemediationSpec } from '../src/types/remediation.js';
import type { HumanApproval } from '../src/types/human-approval.js';

describe('Cryptographic Utilities & Human Approval Binding', () => {
  const testSecret = 'test-secret-at-least-32-characters-long-strictly-enforced';

  it('normalizes CRLF line endings to LF before hashing', () => {
    const crlf = 'line1\r\nline2\r\n';
    const lf = 'line1\nline2\n';
    assert.equal(computeDiffHash(crlf), computeDiffHash(lf));
  });

  it('computes deterministic diff hash regardless of patch array ordering', () => {
    const patchA = {
      path: 'src/a.ts',
      action: 'MODIFY' as const,
      patchDiff: '+ a = 1;'
    };
    const patchB = {
      path: 'src/b.ts',
      action: 'MODIFY' as const,
      patchDiff: '+ b = 2;'
    };

    const hash1 = computeDiffHash([patchA, patchB]);
    const hash2 = computeDiffHash([patchB, patchA]);
    assert.equal(hash1, hash2);
    assert.match(hash1, /^[a-f0-9]{64}$/);
  });

  it('validates a legitimate human approval matching the exact spec and diff hash', () => {
    const diff = '--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new';
    const diffHash = computeDiffHash(diff);
    const specId = 'spec_test_123';
    const userId = 'usr_lead_maintainer';
    const approvedAt = new Date().toISOString();
    const approvalId = randomUUID();
    const nonce = 'a1b2c3d4e5f6g7h8';

    const signature = computeApprovalSignature(
      approvalId,
      specId,
      diffHash,
      userId,
      approvedAt,
      nonce,
      testSecret
    );

    const mockSpec: RemediationSpec = {
      id: specId,
      incidentId: 'INC-01',
      createdAt: approvedAt,
      targetRepository: 'owner/repo',
      baseBranch: 'main',
      targetBranch: 'devpulse/fix',
      errorSignature: 'Error',
      rootCause: 'Root cause',
      patches: [{ path: 'file.ts', action: 'MODIFY', patchDiff: diff }],
      diffHash: diffHash,
      riskReport: {
        riskScore: 10,
        riskLevel: 'LOW',
        blastRadius: ['file.ts'],
        testsImpacted: [],
        rollbackStrategy: 'revert',
        safetyGuarantees: ['none']
      },
      verificationCommands: ['npm test'],
      status: 'TESTS_PASSED'
    };

    const validApproval: HumanApproval = {
      approvalId,
      specId,
      diffHash,
      actor: {
        userId,
        username: 'alice',
        role: 'MAINTAINER',
        channel: 'SWITCH_ROOM'
      },
      decision: 'APPROVED',
      approvedAt,
      nonce,
      signature
    };

    const verification = verifyApprovalIntegrity(validApproval, mockSpec, { secretKey: testSecret });
    assert.equal(verification.valid, true);
  });

  it('rejects human approval if the diff hash was altered', () => {
    const specId = 'spec_test_123';
    const realDiffHash = computeDiffHash('real diff');
    const alteredDiffHash = computeDiffHash('altered malicious diff');
    const userId = 'usr_lead_maintainer';
    const approvedAt = new Date().toISOString();
    const approvalId = randomUUID();
    const nonce = 'nonce123456789012';

    const signature = computeApprovalSignature(
      approvalId,
      specId,
      alteredDiffHash,
      userId,
      approvedAt,
      nonce,
      testSecret
    );

    const mockSpec: RemediationSpec = {
      id: specId,
      incidentId: 'INC-01',
      createdAt: approvedAt,
      targetRepository: 'owner/repo',
      baseBranch: 'main',
      targetBranch: 'devpulse/fix',
      errorSignature: 'Error',
      rootCause: 'Root cause',
      patches: [{ path: 'file.ts', action: 'MODIFY', patchDiff: 'real diff' }],
      diffHash: realDiffHash,
      riskReport: {
        riskScore: 10,
        riskLevel: 'LOW',
        blastRadius: ['file.ts'],
        testsImpacted: [],
        rollbackStrategy: 'revert',
        safetyGuarantees: ['none']
      },
      verificationCommands: ['npm test'],
      status: 'TESTS_PASSED'
    };

    const forgedApproval: HumanApproval = {
      approvalId,
      specId,
      diffHash: alteredDiffHash,
      actor: {
        userId,
        username: 'alice',
        role: 'MAINTAINER',
        channel: 'SWITCH_ROOM'
      },
      decision: 'APPROVED',
      approvedAt,
      nonce,
      signature
    };

    const verification = verifyApprovalIntegrity(forgedApproval, mockSpec, { secretKey: testSecret });
    assert.equal(verification.valid, false);
    assert.match(verification.reason!, /does not match spec diffHash/);
  });

  it('rejects approvals originating outside the Switch room', () => {
    const diffHash = computeDiffHash('diff');
    const specId = 'spec_1';
    const userId = 'usr_1';
    const approvedAt = new Date().toISOString();
    const approvalId = randomUUID();
    const nonce = 'nonce123456789012';
    const signature = computeApprovalSignature(
      approvalId,
      specId,
      diffHash,
      userId,
      approvedAt,
      nonce,
      testSecret
    );

    const mockSpec: RemediationSpec = {
      id: specId,
      incidentId: 'INC-01',
      createdAt: approvedAt,
      targetRepository: 'owner/repo',
      baseBranch: 'main',
      targetBranch: 'devpulse/fix',
      errorSignature: 'Error',
      rootCause: 'Root cause',
      patches: [{ path: 'file.ts', action: 'MODIFY', patchDiff: 'diff' }],
      diffHash: diffHash,
      riskReport: {
        riskScore: 10,
        riskLevel: 'LOW',
        blastRadius: ['file.ts'],
        testsImpacted: [],
        rollbackStrategy: 'revert',
        safetyGuarantees: ['none']
      },
      verificationCommands: ['npm test'],
      status: 'TESTS_PASSED'
    };

    const externalApproval: any = {
      approvalId,
      specId,
      diffHash,
      actor: {
        userId,
        username: 'alice',
        role: 'MAINTAINER',
        channel: 'UNTRUSTED_GITHUB_COMMENT'
      },
      decision: 'APPROVED',
      approvedAt,
      nonce,
      signature
    };

    const verification = verifyApprovalIntegrity(externalApproval, mockSpec, { secretKey: testSecret });
    assert.equal(verification.valid, false);
    assert.match(verification.reason!, /not an authorized Switch room/);
  });
});
