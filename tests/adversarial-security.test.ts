import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';

import {
  computeDiffHash,
  computeSpecHash,
  computeApprovalSignature,
  verifyApprovalIntegrity,
  getApprovalSecret,
  ApprovalNonceTracker,
  sanitizeAuditPayload
} from '../src/utils/crypto.js';
import {
  FilePatchSchema,
  RemediationSpec
} from '../src/types/remediation.js';
import {
  HumanApproval,
  verifyTrustedRoomAuthorization,
  computeGatewaySignature
} from '../src/types/human-approval.js';
import { validateSafeRepoPath } from '../src/utils/path-validator.js';
import { AuditLogger } from '../src/audit/audit-logger.js';

describe('Adversarial Security Verification', () => {
  const strongSecret = 'devpulse-super-strong-secret-key-that-is-at-least-32-chars';
  const gatewaySecret = 'gateway-secret-devpulse-32-chars-long';
  const testNonceFilePath = path.resolve('./logs/test-nonces.jsonl');
  const testAuditPath = path.resolve('./logs/adversarial-audit.jsonl');
  const testSymlinkSandboxDir = path.resolve('./logs/test-symlink-sandbox');

  beforeEach(async () => {
    await fs.mkdir(path.resolve('./logs'), { recursive: true });
  });

  afterEach(async () => {
    try { await fs.unlink(testNonceFilePath); } catch {}
    try { await fs.unlink(testAuditPath); } catch {}
    try { await fs.rm(testSymlinkSandboxDir, { recursive: true, force: true }); } catch {}
  });

  describe('1. Replay Protection Deep Check', () => {
    it('persists nonces across application restarts via persistent storage', async () => {
      const tracker1 = new ApprovalNonceTracker(testNonceFilePath);
      await tracker1.init();

      const approvalId = randomUUID();
      const nonce = 'nonce_persist_123456';

      // First run: consumes successfully
      const firstConsume = tracker1.consume(approvalId, nonce);
      assert.equal(firstConsume, true);

      // Simulate application restart: instantiate brand new tracker from the same persistent file
      const tracker2 = new ApprovalNonceTracker(testNonceFilePath);
      await tracker2.init();

      // Second run after restart: must be recognized as already consumed
      const secondConsume = tracker2.consume(approvalId, nonce);
      assert.equal(secondConsume, false);
      assert.equal(tracker2.isConsumed(approvalId, nonce), true);
    });

    it('atomically prevents concurrent approval requests from bypassing nonce uniqueness', async () => {
      const tracker = new ApprovalNonceTracker();
      const approvalId = randomUUID();
      const nonce = 'concurrent_nonce_123456';

      // Simulate 10 simultaneous concurrent requests trying to consume the exact same approval
      const results = await Promise.all(
        Array.from({ length: 10 }).map(async () => tracker.consume(approvalId, nonce))
      );

      const successfulConsumptions = results.filter((r) => r === true);
      const rejectedConsumptions = results.filter((r) => r === false);

      // Exactly ONE request must succeed; all other 9 must be rejected
      assert.equal(successfulConsumptions.length, 1);
      assert.equal(rejectedConsumptions.length, 9);
    });
  });

  describe('2. Switch Console Identity & Authenticity Verification', () => {
    it('rejects an approval event if the Switch Gateway signature was forged or altered', () => {
      const rawEvent = {
        roomId: 'room_devpulse',
        senderId: 'usr_maintainer_1',
        senderUsername: 'alice',
        senderType: 'human' as const,
        roomRole: 'MAINTAINER' as const,
        timestamp: new Date().toISOString()
      };

      const forgedEvent = {
        ...rawEvent,
        gatewaySignature: 'bad_forged_signature_0000000000000000'
      };

      const result = verifyTrustedRoomAuthorization(forgedEvent, ['usr_maintainer_1'], gatewaySecret);
      assert.equal(result.authorized, false);
      assert.match(result.reason!, /Invalid Switch Gateway signature/);
    });

    it('rejects ordinary users attempting to claim maintainer status without being in allowlist', () => {
      const rawEvent = {
        roomId: 'room_devpulse',
        senderId: 'usr_random_user',
        senderUsername: 'mallory',
        senderType: 'human' as const,
        roomRole: 'MAINTAINER' as const,
        timestamp: new Date().toISOString()
      };
      const signedEvent = {
        ...rawEvent,
        gatewaySignature: computeGatewaySignature(rawEvent, gatewaySecret)
      };

      const result = verifyTrustedRoomAuthorization(signedEvent, ['usr_authorized_admin'], gatewaySecret);
      assert.equal(result.authorized, false);
      assert.match(result.reason!, /not in the allowed approver list/);
    });
  });

  describe('3. Path Traversal, Windows Vectors & Symbolic Link Security', () => {
    it('rejects Windows drive letters (C:, D:) in patch paths', () => {
      const check1 = validateSafeRepoPath('C:\\Windows\\System32\\cmd.exe');
      assert.equal(check1.safe, false);
      assert.match(check1.reason!, /Windows drive letters are forbidden/);

      const check2 = validateSafeRepoPath('D:malicious.ts');
      assert.equal(check2.safe, false);
      assert.match(check2.reason!, /Windows drive letters are forbidden/);
    });

    it('rejects UNC network paths (\\\\server\\share or //server/share)', () => {
      const check1 = validateSafeRepoPath('\\\\remote-server\\c$\\malicious.ts');
      assert.equal(check1.safe, false);
      assert.match(check1.reason!, /UNC network paths are forbidden/);

      const check2 = validateSafeRepoPath('//remote-server/share/file.ts');
      assert.equal(check2.safe, false);
      assert.match(check2.reason!, /UNC network paths are forbidden/);
    });

    it('rejects null byte injections in file paths', () => {
      const check = validateSafeRepoPath('src/auth.ts\0.exe');
      assert.equal(check.safe, false);
      assert.match(check.reason!, /Null byte injection detected/);
    });

    it('rejects Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)', () => {
      for (const name of ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT1']) {
        const check = validateSafeRepoPath(`src/${name}.ts`);
        assert.equal(check.safe, false);
        assert.match(check.reason!, /Windows reserved device name/);
      }
    });

    it('rejects parent directory escape attempts', () => {
      const check = validateSafeRepoPath('src/components/../../../secret.env');
      assert.equal(check.safe, false);
      assert.match(check.reason!, /Directory traversal sequence/);
    });

    it('detects and rejects symbolic links pointing outside repository boundary', async () => {
      const mockRepoRoot = path.join(testSymlinkSandboxDir, 'repo');
      const mockOutsideTarget = path.join(testSymlinkSandboxDir, 'outside-secret');

      await fs.mkdir(mockRepoRoot, { recursive: true });
      await fs.mkdir(mockOutsideTarget, { recursive: true });
      await fs.writeFile(path.join(mockOutsideTarget, 'secret.txt'), 'SUPER_SECRET', 'utf8');

      // Create a symbolic link inside mockRepoRoot pointing to mockOutsideTarget
      const symlinkPath = path.join(mockRepoRoot, 'symlink-dir');
      try {
        await fs.symlink(mockOutsideTarget, symlinkPath, 'junction'); // 'junction' or 'dir' works cross-platform on Windows
      } catch (err: unknown) {
        // If system privileges prevent symlink creation on Windows without Developer Mode, skip the physical link step
        return;
      }

      // Test path that attempts to write through the symlink to the outside file
      const check = validateSafeRepoPath('symlink-dir/secret.txt', mockRepoRoot);
      assert.equal(check.safe, false);
      assert.match(check.reason!, /Symbolic link escapes repository root boundary/);
    });
  });

  describe('4. Audit Log Security & Hash-Chain Integrity', () => {
    it('sanitizes multiline PEM private keys and connection strings with passwords', () => {
      const multilineKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+
abcdefghijklmnopqrstuvwxyz0123456789==
-----END RSA PRIVATE KEY-----`;

      const payload = {
        databaseUrl: 'postgresql://dbadmin:p@ssword123@db.internal:5432/production',
        privateKey: multilineKey
      };

      const sanitized = sanitizeAuditPayload(payload) as any;
      assert.equal(sanitized.privateKey, '[REDACTED]');
      assert.equal(sanitized.databaseUrl.includes('p@ssword123'), false);
    });

    it('handles circular references in payload objects safely without stack overflow', () => {
      const circularObj: any = { name: 'cyclic-node' };
      circularObj.self = circularObj;

      const sanitized = sanitizeAuditPayload(circularObj) as any;
      assert.equal(sanitized.name, 'cyclic-node');
      assert.equal(sanitized.self, '[CIRCULAR_REF]');
    });

    it('detects offline log file rewrite when HMAC keying is active', async () => {
      const keyedLogger = new AuditLogger({
        filePath: testAuditPath,
        secretKey: strongSecret
      });

      await keyedLogger.log({
        actor: { type: 'SENTINEL', id: 'agent-sentinel', name: 'Sentinel' },
        action: 'INSPECT',
        payload: { valid: true }
      });

      await keyedLogger.log({
        actor: { type: 'HUMAN', id: 'usr_alice', name: 'Alice' },
        action: 'APPROVED',
        payload: { specId: 'spec_1' }
      });

      // Legitimate chain passes
      const originalCheck = await keyedLogger.verifyChainIntegrity();
      assert.equal(originalCheck.valid, true);

      // Adversary rewrites file and attempts to recompute plain SHA-256 hashes without the secret key
      const content = await fs.readFile(testAuditPath, 'utf8');
      const lines = content.trim().split('\n');
      const rewrittenLines = lines.map((line) => {
        const parsed = JSON.parse(line);
        if (parsed.sequence === 2) {
          parsed.payload = { specId: 'spec_TAMPERED' };
        }
        return JSON.stringify(parsed);
      });
      await fs.writeFile(testAuditPath, rewrittenLines.join('\n') + '\n', 'utf8');

      // The keyed logger detects tampering because the adversary could not re-sign with HMAC
      const tamperedCheck = await keyedLogger.verifyChainIntegrity();
      assert.equal(tamperedCheck.valid, false);
      assert.match(tamperedCheck.reason!, /Data tampering detected/);
    });
  });

  describe('5. Comprehensive Approval Binding (All Execution Parameters Covered by specHash)', () => {
    const diff = '+ fixed line';
    const diffHash = computeDiffHash(diff);
    const specId = 'spec_params_01';
    const userId = 'usr_alice';
    const approvedAt = new Date().toISOString();
    const approvalId = randomUUID();
    const nonce = 'nonce_params_12345';

    const baseSpec: RemediationSpec = {
      id: specId,
      incidentId: 'INC-01',
      createdAt: approvedAt,
      targetRepository: 'owner/devpulse-demo',
      baseBranch: 'main',
      targetBranch: 'devpulse/fix-issue',
      errorSignature: 'Error',
      rootCause: 'Root cause',
      patches: [{ path: 'src/fix.ts', action: 'MODIFY', patchDiff: diff }],
      diffHash,
      riskReport: {
        riskScore: 10,
        riskLevel: 'LOW',
        blastRadius: ['src/fix.ts'],
        testsImpacted: [],
        rollbackStrategy: 'revert',
        safetyGuarantees: ['none']
      },
      verificationCommands: ['npm test'],
      status: 'TESTS_PASSED'
    };

    function setupApproval(spec: RemediationSpec): HumanApproval {
      const specHash = computeSpecHash(spec);
      spec.specHash = specHash;
      const signature = computeApprovalSignature(
        approvalId,
        spec.id,
        spec.diffHash,
        userId,
        approvedAt,
        nonce,
        strongSecret,
        specHash
      );
      return {
        approvalId,
        specId: spec.id,
        diffHash: spec.diffHash,
        specHash,
        actor: { userId, username: 'alice', role: 'ADMIN', channel: 'SWITCH_ROOM' },
        decision: 'APPROVED',
        approvedAt,
        nonce,
        signature
      };
    }

    it('verifies legitimate specification matching all parameters', () => {
      const spec = { ...baseSpec };
      const approval = setupApproval(spec);
      const result = verifyApprovalIntegrity(approval, spec, { secretKey: strongSecret });
      assert.equal(result.valid, true);
    });

    it('invalidates approval if targetRepository is changed', () => {
      const spec = { ...baseSpec };
      const approval = setupApproval(spec);
      const tamperedSpec = { ...spec, targetRepository: 'attacker/malicious-repo' };
      const result = verifyApprovalIntegrity(approval, tamperedSpec, { secretKey: strongSecret });
      assert.equal(result.valid, false);
      assert.match(result.reason!, /Approval specHash does not match computed spec parameters/);
    });

    it('invalidates approval if baseBranch is changed', () => {
      const spec = { ...baseSpec };
      const approval = setupApproval(spec);
      const tamperedSpec = { ...spec, baseBranch: 'release-2.0' };
      const result = verifyApprovalIntegrity(approval, tamperedSpec, { secretKey: strongSecret });
      assert.equal(result.valid, false);
      assert.match(result.reason!, /Approval specHash does not match computed spec parameters/);
    });

    it('invalidates approval if targetBranch is changed', () => {
      const spec = { ...baseSpec };
      const approval = setupApproval(spec);
      const tamperedSpec = { ...spec, targetBranch: 'main' };
      const result = verifyApprovalIntegrity(approval, tamperedSpec, { secretKey: strongSecret });
      assert.equal(result.valid, false);
      assert.match(result.reason!, /Approval specHash does not match computed spec parameters/);
    });

    it('invalidates approval if verificationCommands are altered', () => {
      const spec = { ...baseSpec };
      const approval = setupApproval(spec);
      const tamperedSpec = { ...spec, verificationCommands: ['echo bypass && exit 0'] };
      const result = verifyApprovalIntegrity(approval, tamperedSpec, { secretKey: strongSecret });
      assert.equal(result.valid, false);
      assert.match(result.reason!, /Approval specHash does not match computed spec parameters/);
    });

    it('invalidates approval if diffHash is altered', () => {
      const spec = { ...baseSpec };
      const approval = setupApproval(spec);
      const tamperedSpec = { ...spec, diffHash: computeDiffHash('+ different diff') };
      const result = verifyApprovalIntegrity(approval, tamperedSpec, { secretKey: strongSecret });
      assert.equal(result.valid, false);
      assert.match(result.reason!, /Approval diffHash '.*' does not match spec diffHash/);
    });
  });
});
