import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';

import {
  computeDiffHash,
  computeApprovalSignature,
  verifyApprovalIntegrity,
  getApprovalSecret,
  ApprovalNonceTracker
} from '../src/utils/crypto.js';
import {
  FilePatchSchema,
  RemediationSpec
} from '../src/types/remediation.js';
import {
  HumanApproval,
  verifyTrustedRoomAuthorization,
  SwitchRoomEventMetadata,
  computeGatewaySignature
} from '../src/types/human-approval.js';
import { AuditLogger } from '../src/audit/audit-logger.js';

describe('Security Hardening & Threat Verification', () => {
  const strongSecret = 'devpulse-super-strong-secret-key-that-is-at-least-32-chars';
  const gatewaySecret = 'gateway-secret-devpulse-32-chars-long';
  const testLogPath = path.resolve('./logs/security-test-audit.jsonl');
  let logger: AuditLogger;

  beforeEach(async () => {
    await fs.mkdir(path.resolve('./logs'), { recursive: true });
    logger = new AuditLogger({ filePath: testLogPath });
    await logger.clear();
  });

  afterEach(async () => {
    await logger.clear();
  });

  describe('1. Switch Room Identity & Trusted Authorization', () => {
    it('approves legitimate human maintainers in Switch room with valid gateway signature', () => {
      const unsigned = {
        roomId: 'room_devpulse_ops',
        senderId: 'usr_sec_lead',
        senderUsername: 'alice',
        senderType: 'human' as const,
        roomRole: 'SECURITY_LEAD' as const,
        timestamp: new Date().toISOString()
      };
      const gatewaySignature = computeGatewaySignature(unsigned, gatewaySecret);

      const trustedEvent: SwitchRoomEventMetadata = {
        ...unsigned,
        gatewaySignature
      };

      const result = verifyTrustedRoomAuthorization(trustedEvent, ['usr_sec_lead'], gatewaySecret);
      assert.equal(result.authorized, true);
    });

    it('rejects bot or agent sender types attempting to issue approvals', () => {
      const unsigned = {
        roomId: 'room_devpulse_ops',
        senderId: 'bot_rogue_agent',
        senderUsername: 'rogue-bot',
        senderType: 'agent',
        roomRole: 'ADMIN',
        timestamp: new Date().toISOString()
      };
      const botEvent: any = {
        ...unsigned,
        gatewaySignature: 'sig'
      };

      const result = verifyTrustedRoomAuthorization(botEvent);
      assert.equal(result.authorized, false);
      assert.match(result.reason!, /Only human operators may issue approvals/);
    });

    it('rejects human users not present in the authorized approver allowlist', () => {
      const unsigned = {
        roomId: 'room_devpulse_ops',
        senderId: 'usr_external_contributor',
        senderUsername: 'mallory',
        senderType: 'human' as const,
        roomRole: 'MAINTAINER' as const,
        timestamp: new Date().toISOString()
      };
      const unauthorizedUser: SwitchRoomEventMetadata = {
        ...unsigned,
        gatewaySignature: computeGatewaySignature(unsigned, gatewaySecret)
      };

      const result = verifyTrustedRoomAuthorization(unauthorizedUser, ['usr_lead_maintainer'], gatewaySecret);
      assert.equal(result.authorized, false);
      assert.match(result.reason!, /not in the allowed approver list/);
    });
  });

  describe('2. Secret Key Configuration & Management', () => {
    it('refuses to operate if secret is shorter than 32 characters', () => {
      assert.throws(
        () => getApprovalSecret('short-weak-key'),
        /must be at least 32 characters long/
      );
    });
  });

  describe('3. Replay Protection & Timestamp Freshness', () => {
    const specId = 'spec_sec_01';
    const diffHash = computeDiffHash('valid diff');
    const userId = 'usr_alice';

    const mockSpec: RemediationSpec = {
      id: specId,
      incidentId: 'INC-SEC-01',
      createdAt: new Date().toISOString(),
      targetRepository: 'owner/repo',
      baseBranch: 'main',
      targetBranch: 'devpulse/fix',
      errorSignature: 'Error',
      rootCause: 'Root cause',
      patches: [{ path: 'file.ts', action: 'MODIFY', patchDiff: 'valid diff' }],
      diffHash,
      riskReport: {
        riskScore: 5,
        riskLevel: 'LOW',
        blastRadius: ['file.ts'],
        testsImpacted: [],
        rollbackStrategy: 'revert',
        safetyGuarantees: ['none']
      },
      verificationCommands: ['npm test'],
      status: 'TESTS_PASSED'
    };

    it('rejects expired approvals older than allowed maxAge', () => {
      const expiredDate = new Date(Date.now() - 10 * 60 * 1000).toISOString();
      const approvalId = randomUUID();
      const nonce = 'nonce123456789012';
      const signature = computeApprovalSignature(
        approvalId,
        specId,
        diffHash,
        userId,
        expiredDate,
        nonce,
        strongSecret
      );

      const expiredApproval: HumanApproval = {
        approvalId,
        specId,
        diffHash,
        actor: { userId, username: 'alice', role: 'ADMIN', channel: 'SWITCH_ROOM' },
        decision: 'APPROVED',
        approvedAt: expiredDate,
        nonce,
        signature
      };

      const result = verifyApprovalIntegrity(expiredApproval, mockSpec, {
        secretKey: strongSecret,
        maxAgeMs: 5 * 60 * 1000
      });
      assert.equal(result.valid, false);
      assert.match(result.reason!, /Approval timestamp is expired/);
    });

    it('rejects approval timestamps set in the future', () => {
      const futureDate = new Date(Date.now() + 60 * 1000).toISOString();
      const approvalId = randomUUID();
      const nonce = 'nonce123456789012';
      const signature = computeApprovalSignature(
        approvalId,
        specId,
        diffHash,
        userId,
        futureDate,
        nonce,
        strongSecret
      );

      const futureApproval: HumanApproval = {
        approvalId,
        specId,
        diffHash,
        actor: { userId, username: 'alice', role: 'ADMIN', channel: 'SWITCH_ROOM' },
        decision: 'APPROVED',
        approvedAt: futureDate,
        nonce,
        signature
      };

      const result = verifyApprovalIntegrity(futureApproval, mockSpec, { secretKey: strongSecret });
      assert.equal(result.valid, false);
      assert.match(result.reason!, /timestamp is in the future/);
    });

    it('detects and halts replay attacks using the same approval ID and nonce', () => {
      const tracker = new ApprovalNonceTracker();
      const approvalDate = new Date().toISOString();
      const approvalId = randomUUID();
      const nonce = 'nonce123456789012';
      const signature = computeApprovalSignature(
        approvalId,
        specId,
        diffHash,
        userId,
        approvalDate,
        nonce,
        strongSecret
      );

      const approval: HumanApproval = {
        approvalId,
        specId,
        diffHash,
        actor: { userId, username: 'alice', role: 'ADMIN', channel: 'SWITCH_ROOM' },
        decision: 'APPROVED',
        approvedAt: approvalDate,
        nonce,
        signature
      };

      const firstTry = verifyApprovalIntegrity(approval, mockSpec, {
        secretKey: strongSecret,
        nonceTracker: tracker
      });
      assert.equal(firstTry.valid, true);

      const secondTry = verifyApprovalIntegrity(approval, mockSpec, {
        secretKey: strongSecret,
        nonceTracker: tracker
      });
      assert.equal(secondTry.valid, false);
      assert.match(secondTry.reason!, /Replay attack detected/);
    });
  });

  describe('4. Diff Hashing & Patch Path Traversal Resistance', () => {
    it('rejects path traversal attempts in FilePatchSchema', () => {
      assert.throws(() => {
        FilePatchSchema.parse({
          path: '../../etc/passwd',
          action: 'MODIFY',
          patchDiff: 'exploit'
        });
      });

      assert.throws(() => {
        FilePatchSchema.parse({
          path: '/etc/shadow',
          action: 'MODIFY',
          patchDiff: 'exploit'
        });
      });
    });

    it('rejects pure whitespace diffs', () => {
      assert.throws(() => {
        FilePatchSchema.parse({
          path: 'src/file.ts',
          action: 'MODIFY',
          patchDiff: '   \n  \t  '
        });
      }, /cannot be purely whitespace/);
    });
  });

  describe('5. Audit Logger Concurrency & Truncation Handling', () => {
    it('handles high concurrent writes safely without sequence duplication or chain breakage', async () => {
      const totalConcurrent = 15;
      const promises: Promise<any>[] = [];

      for (let i = 0; i < totalConcurrent; i++) {
        promises.push(
          logger.log({
            actor: { type: 'SENTINEL', id: 'agent-sentinel', name: 'Sentinel' },
            action: `CONCURRENT_EVENT_${i}`,
            payload: { iteration: i }
          })
        );
      }

      await Promise.all(promises);

      const { entries } = await logger.getEntries();
      assert.equal(entries.length, totalConcurrent);

      for (let i = 0; i < totalConcurrent; i++) {
        assert.equal(entries[i]!.sequence, i + 1);
      }

      const verification = await logger.verifyChainIntegrity();
      assert.equal(verification.valid, true);
    });

    it('identifies file truncation or corrupted partial JSON lines', async () => {
      await logger.log({
        actor: { type: 'SYSTEM', id: 'sys', name: 'System' },
        action: 'BOOTSTRAP',
        payload: { ok: true }
      });

      await fs.appendFile(testLogPath, '{"id":"incomplete-trunca\n', 'utf8');

      const result = await logger.verifyChainIntegrity();
      assert.equal(result.valid, false);
      assert.match(result.reason!, /File corruption or truncation/);
    });
  });

  describe('6. Credential & Secret Redaction in Audit Logging', () => {
    it('automatically sanitizes sensitive keys and token formats before writing to audit log', async () => {
      const sensitivePayload = {
        repository: 'owner/repo',
        githubToken: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
        bearerAuth: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M',
        api_key: 'super-secret-key-12345',
        nested: {
          password: 'my-unencrypted-password',
          safeField: 'visible-data'
        }
      };

      const entry = await logger.log({
        actor: { type: 'SENTINEL', id: 'agent-sentinel', name: 'Sentinel' },
        action: 'INSPECT_PAYLOAD',
        payload: sensitivePayload
      });

      const rawFileContent = await fs.readFile(testLogPath, 'utf8');

      assert.equal(rawFileContent.includes('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), false);
      assert.equal(rawFileContent.includes('super-secret-key-12345'), false);
      assert.equal(rawFileContent.includes('my-unencrypted-password'), false);

      assert.equal(entry.payload['githubToken'], '[REDACTED]');
      assert.equal(entry.payload['api_key'], '[REDACTED]');
      assert.equal((entry.payload['nested'] as any)['password'], '[REDACTED]');
      assert.equal((entry.payload['nested'] as any)['safeField'], 'visible-data');
    });
  });
});
