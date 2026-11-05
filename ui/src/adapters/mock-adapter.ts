import {
  Incident,
  MemoryRecord,
  AuditEntry,
  ApprovalRequest,
  ApprovalResult,
  DevPulseAdapter
} from './types';
import { GENESIS_HASH, computeAuditHash } from '../utils/crypto';

export const ALLOWED_MAINTAINERS = [
  'dr_sarah_lin',
  'lead_physician_chen',
  'attending_sre_alvarez'
];

export const AUTHORIZED_SWITCH_ORIGIN = 'SWITCH_ROOM';

export class MockDevPulseAdapter implements DevPulseAdapter {
  private incidents: Incident[] = [];
  private memoryRecords: MemoryRecord[] = [];
  private auditEntries: AuditEntry[] = [];
  private consumedChallenges = new Set<string>();

  constructor() {
    this.seedData();
  }

  private async seedData() {
    const now = Date.now();

    // 1. Memory Records
    this.memoryRecords = [
      {
        id: 'REC-7210',
        signature: 'TypeError: Cannot read properties of null (reading "sub") at SessionVerifier.verifyToken',
        rootCause: 'Expired session claims cached as null without validation guard before property access.',
        fix: 'Add explicit guard `if (!decoded || !decoded.sub) throw new AuthSessionExpiredError(...)` before property access.',
        verified: true,
        createdAt: new Date(now - 86400000 * 4).toISOString(),
        similarity: 94
      },
      {
        id: 'REC-6114',
        signature: 'RangeError: Maximum call stack size exceeded at WorkerDispatcher.pollNextBatch',
        rootCause: 'Recursive poll without exponential backoff on zero-length batch under burst drain.',
        fix: 'Add computeJitterBackoff delay and replace recursive loop with iterative token-bucket drain.',
        verified: true,
        createdAt: new Date(now - 86400000 * 12).toISOString(),
        similarity: 88
      },
      {
        id: 'REC-5890',
        signature: 'JsonWebTokenError: jwt not active yet at TokenValidator.assertActive',
        rootCause: 'Clock skew between distributed nodes caused premature validation failure for newly minted tokens.',
        fix: 'Provide clockTolerance: 30 seconds parameter to jwt.verify claims assertions.',
        verified: true,
        createdAt: new Date(now - 86400000 * 20).toISOString(),
        similarity: 78
      },
      {
        id: 'REC-5102',
        signature: 'TimeoutError: Connection pool acquisition timed out after 5000ms',
        rootCause: 'Connection leak during unhandled promise rejection in transaction rollback block.',
        fix: 'Ensure client.release() in mandatory finally block of transactional helper.',
        verified: false,
        createdAt: new Date(now - 86400000 * 35).toISOString(),
        similarity: 65
      }
    ];

    // 2. Incidents
    this.incidents = [
      {
        id: 'INC-8402',
        title: 'Auth session null dereference on token expiry',
        severity: 'critical',
        file: 'src/auth/session-verifier.ts',
        line: 142,
        errorSignature: "TypeError: Cannot read properties of null (reading 'sub') at SessionVerifier.verifyToken",
        rootCause: 'Decrypted session payload returns null when cached token has elapsed TTL, causing immediate null pointer dereference on .sub access.',
        stage: 5, // Challenge active
        admittedAt: new Date(now - 78000).toISOString(),
        precedent: {
          id: 'REC-7210',
          similarity: 94,
          fix: 'Add explicit guard `if (!decoded || !decoded.sub) throw new AuthSessionExpiredError(...)` before property access.',
          verified: true
        },
        diff: `--- a/src/auth/session-verifier.ts
+++ b/src/auth/session-verifier.ts
@@ -140,4 +140,8 @@ export async function verifyToken(rawToken: string): Promise<SessionClaims> {
   const decoded = await decryptSessionClaims(rawToken);
+  if (!decoded || typeof decoded.sub !== 'string') {
+    throw new AuthSessionExpiredError('Session claims missing or invalidated');
+  }
   return decoded;
 }`,
        specHash: '7f8c12e52b3491ea94cd09918a38b1f7e029471b6982cb12d4a51e6008b83a19',
        challenge: {
          id: 'appr_8402_a1',
          expiresAt: new Date(now + 222000).toISOString(), // ~3m 42s remaining
          status: 'open'
        },
        sandbox: {
          flags: ['--network none', 'read-only rootfs', 'non-root: sandbox_user'],
          lines: [
            '[SANDBOX INIT] Mounting isolated filesystem at /workspace/devpulse (read-only)...',
            '[SANDBOX INIT] Setting non-root UID 10001 (sandbox_user)...',
            '[SANDBOX INIT] Network namespace unshared (--network none active)...',
            '[READY] Awaiting maintainer two-key authorization...'
          ],
          exitCode: null,
          durationMs: 0
        }
      },
      {
        id: 'INC-8409',
        title: 'Queue worker recursive spin loop on empty batch',
        severity: 'high',
        file: 'src/queue/worker-dispatcher.ts',
        line: 88,
        errorSignature: 'RangeError: Maximum call stack size exceeded at WorkerDispatcher.pollNextBatch',
        rootCause: 'Worker immediately tail-calls pollNextBatch when dequeue returns 0 jobs without sleep delay, exhausting V8 stack.',
        stage: 5,
        admittedAt: new Date(now - 145000).toISOString(),
        precedent: {
          id: 'REC-6114',
          similarity: 88,
          fix: 'Insert jittered backoff delay before re-polling on empty queue batch.',
          verified: true
        },
        diff: `--- a/src/queue/worker-dispatcher.ts
+++ b/src/queue/worker-dispatcher.ts
@@ -86,4 +86,7 @@ export async function pollNextBatch(queue: WorkQueue): Promise<void> {
   const batch = await queue.dequeue(BATCH_SIZE);
   if (batch.length === 0) {
+    const backoffMs = computeJitterBackoff(queue.backoffCount++);
+    await sleep(backoffMs);
     return pollNextBatch(queue);
   }
   await processBatch(batch);
 }`,
        specHash: 'e2b144fa78c891340b01c183aa639b7d04e38923a129d891632001e95679044',
        challenge: {
          id: 'appr_8409_w2',
          expiresAt: new Date(now + 265000).toISOString(), // ~4m 25s remaining
          status: 'open'
        },
        sandbox: {
          flags: ['--network none', 'read-only rootfs', 'non-root: sandbox_user'],
          lines: [
            '[SANDBOX INIT] Network sandbox engaged (--network none)...',
            '[SANDBOX INIT] Sandboxed runner initialized in ephemeral overlay.',
            '[READY] Awaiting maintainer two-key authorization...'
          ],
          exitCode: null,
          durationMs: 0
        }
      },
      {
        id: 'INC-8395',
        title: 'Configuration loader crash on missing HMAC secret',
        severity: 'medium',
        file: 'src/config/env-loader.ts',
        line: 31,
        errorSignature: 'Error: DEVPULSE_APPROVAL_SECRET environment variable is missing. Refusing to run with insecure default.',
        rootCause: 'Strict production validator rejects null env secret without checking development fallback branch.',
        stage: 8, // Sandbox running tests
        admittedAt: new Date(now - 320000).toISOString(),
        diff: `--- a/src/config/env-loader.ts
+++ b/src/config/env-loader.ts
@@ -29,3 +29,6 @@ export function loadGateSecret(): string {
   const secret = process.env['DEVPULSE_APPROVAL_SECRET'];
   if (!secret || secret.length < 32) {
+    if (process.env['NODE_ENV'] === 'development') {
+      return 'dev-ephemeral-test-secret-devpulse-32-chars-long';
+    }
     throw new Error('DEVPULSE_APPROVAL_SECRET is missing');
   }`,
        specHash: '41de99c011e4f9b8970034a118e6b359f80164a382dfa52b1239aa8e0998c02',
        challenge: {
          id: 'appr_8395_c3',
          expiresAt: new Date(now - 12000).toISOString(),
          status: 'consumed'
        },
        sandbox: {
          flags: ['--network none', 'read-only rootfs', 'non-root: sandbox_user'],
          lines: [
            '[SANDBOX INIT] --network none, read-only rootfs, non-root uid: 10001',
            '[RUNNER] Human authorization verified: dr_sarah_lin (SWITCH_ROOM)',
            '[RUNNER] Applying patch spec 41de99c0...',
            '[RUNNER] Patch applied cleanly to src/config/env-loader.ts (1 hunk)',
            '[RUNNER] Executing: node --test tests/config-loader.test.ts',
            '✔ should load production key when present (14ms)',
            '✔ should allow development fallback only when NODE_ENV=development (8ms)',
            '[EVIDENCE] All 2 test suites passed without regressions.'
          ],
          exitCode: 0,
          durationMs: 1420
        }
      },
      {
        id: 'INC-8380',
        title: 'Database connection pool acquisition timeout',
        severity: 'low',
        file: 'src/db/pool-alloc.ts',
        line: 74,
        errorSignature: 'TimeoutError: ResourceRequest timed out after 5000ms at Pool.acquire',
        rootCause: 'Idle connections dropped by upstream firewall without client keepalive.',
        stage: 9, // Remembered / Discharged
        admittedAt: new Date(now - 7200000).toISOString(),
        resolvedAt: new Date(now - 3600000).toISOString(),
        diff: `--- a/src/db/pool-alloc.ts
+++ b/src/db/pool-alloc.ts
@@ -72,2 +72,3 @@ export const pool = new Pool({
   max: 20,
+  idleTimeoutMillis: 30000,
   connectionTimeoutMillis: 5000
 });`,
        specHash: '9a20fe1128394bc88192a01726481023bc49281a8c8821948129e00184b81920',
        challenge: {
          id: 'appr_8380_x0',
          expiresAt: new Date(now - 7000000).toISOString(),
          status: 'consumed'
        },
        sandbox: {
          flags: ['--network none', 'read-only rootfs', 'non-root: sandbox_user'],
          lines: [
            '[RUNNER] Patch applied cleanly to src/db/pool-alloc.ts',
            '[RUNNER] Verified connection keepalive pool cycle (exit: 0).'
          ],
          exitCode: 0,
          durationMs: 980
        }
      }
    ];

    // 3. Audit Log chained with real SHA-256 Web Crypto
    await this.seedAuditLog();
  }

  private async seedAuditLog() {
    let prev = GENESIS_HASH;
    const initialEvents = [
      {
        seq: 0,
        ts: new Date(Date.now() - 3600000 * 2).toISOString(),
        event: 'GENESIS_INITIALIZED',
        detail: {
          engine: 'DevPulse v0.1.0',
          origin: 'Switch Console (#incident-response-war-room)',
          security: 'HMAC-SHA256 chained'
        }
      },
      {
        seq: 1,
        ts: new Date(Date.now() - 3600000).toISOString(),
        event: 'INCIDENT_ADMITTED',
        detail: {
          incidentId: 'INC-8380',
          culprit: 'src/db/pool-alloc.ts:74',
          severity: 'low',
          specHash: '9a20fe1128394bc88192a01726481023bc49281a8c8821948129e00184b81920'
        }
      },
      {
        seq: 2,
        ts: new Date(Date.now() - 3550000).toISOString(),
        event: 'CHALLENGE_ISSUED',
        detail: {
          incidentId: 'INC-8380',
          challengeId: 'appr_8380_x0',
          ttlSeconds: 300,
          specHash: '9a20fe1128394bc88192a01726481023bc49281a8c8821948129e00184b81920'
        }
      },
      {
        seq: 3,
        ts: new Date(Date.now() - 3500000).toISOString(),
        event: 'CHALLENGE_AUTHORIZED',
        detail: {
          incidentId: 'INC-8380',
          challengeId: 'appr_8380_x0',
          approver: 'dr_sarah_lin',
          origin: 'SWITCH_ROOM',
          status: 'ACCEPTED'
        }
      },
      {
        seq: 4,
        ts: new Date(Date.now() - 3400000).toISOString(),
        event: 'SANDBOX_EXECUTED',
        detail: {
          incidentId: 'INC-8380',
          sandboxFlags: ['--network none', 'read-only rootfs', 'non-root: sandbox_user'],
          exitCode: 0,
          durationMs: 980
        }
      },
      {
        seq: 5,
        ts: new Date(Date.now() - 3300000).toISOString(),
        event: 'MEMORY_RECORDED',
        detail: {
          incidentId: 'INC-8380',
          memoryId: 'REC-5102',
          verified: true
        }
      },
      {
        seq: 6,
        ts: new Date(Date.now() - 78000).toISOString(),
        event: 'INCIDENT_ADMITTED',
        detail: {
          incidentId: 'INC-8402',
          culprit: 'src/auth/session-verifier.ts:142',
          severity: 'critical',
          specHash: '7f8c12e52b3491ea94cd09918a38b1f7e029471b6982cb12d4a51e6008b83a19'
        }
      },
      {
        seq: 7,
        ts: new Date(Date.now() - 76000).toISOString(),
        event: 'CHALLENGE_ISSUED',
        detail: {
          incidentId: 'INC-8402',
          challengeId: 'appr_8402_a1',
          ttlSeconds: 300,
          specHash: '7f8c12e52b3491ea94cd09918a38b1f7e029471b6982cb12d4a51e6008b83a19'
        }
      }
    ];

    this.auditEntries = [];
    for (const item of initialEvents) {
      const hash = await computeAuditHash(prev, item.seq, item.event, item.detail);
      this.auditEntries.push({
        seq: item.seq,
        ts: item.ts,
        event: item.event,
        detail: item.detail,
        prevHash: prev,
        hash
      });
      prev = hash;
    }
  }

  public async getIncidents(): Promise<Incident[]> {
    return [...this.incidents];
  }

  public async getMemoryRecords(): Promise<MemoryRecord[]> {
    return [...this.memoryRecords];
  }

  public async getAuditEntries(): Promise<AuditEntry[]> {
    return [...this.auditEntries];
  }

  public async appendAudit(event: string, detail: Record<string, unknown>): Promise<AuditEntry> {
    const seq = this.auditEntries.length;
    const prevHash = seq > 0 && this.auditEntries[seq - 1] ? this.auditEntries[seq - 1]!.hash : GENESIS_HASH;
    const ts = new Date().toISOString();
    const hash = await computeAuditHash(prevHash, seq, event, detail);

    const entry: AuditEntry = {
      seq,
      ts,
      event,
      detail,
      prevHash,
      hash
    };

    this.auditEntries.push(entry);
    return entry;
  }

  public async ingestTrace(traceText: string): Promise<Incident> {
    // Realistic stack trace parsing
    let file = 'src/service/worker.ts';
    let line = 42;
    let errorSignature = 'Error: Unexpected runtime failure';
    let rootCause = 'Unhandled exception in worker execution context.';
    let title = 'Runtime assertion failure in worker thread';
    let diff = `--- a/${file}
+++ b/${file}
@@ -40,3 +40,5 @@ export function processJob(job: Job) {
+  if (!job || !job.payload) {
+    throw new InvalidJobError('Job payload is missing');
+  }
   return handle(job.payload);
 }`;

    if (traceText.includes('session-verifier') || traceText.includes('sub') || traceText.includes('TypeError: Cannot read properties of null')) {
      file = 'src/auth/session-verifier.ts';
      line = 142;
      errorSignature = "TypeError: Cannot read properties of null (reading 'sub') at SessionVerifier.verifyToken";
      rootCause = 'Expired session token payload decoded as null without guard before .sub access.';
      title = 'Auth session null dereference on token expiry';
      diff = `--- a/src/auth/session-verifier.ts
+++ b/src/auth/session-verifier.ts
@@ -140,4 +140,8 @@ export async function verifyToken(rawToken: string): Promise<SessionClaims> {
   const decoded = await decryptSessionClaims(rawToken);
+  if (!decoded || typeof decoded.sub !== 'string') {
+    throw new AuthSessionExpiredError('Session claims missing or invalidated');
+  }
   return decoded;
 }`;
    } else if (traceText.includes('worker-dispatcher') || traceText.includes('Maximum call stack size') || traceText.includes('spin')) {
      file = 'src/queue/worker-dispatcher.ts';
      line = 88;
      errorSignature = 'RangeError: Maximum call stack size exceeded at WorkerDispatcher.pollNextBatch';
      rootCause = 'Recursive re-polling of empty queue without backoff triggers call stack exhaustion.';
      title = 'Queue worker recursive spin loop on empty batch';
      diff = `--- a/src/queue/worker-dispatcher.ts
+++ b/src/queue/worker-dispatcher.ts
@@ -86,4 +86,7 @@ export async function pollNextBatch(queue: WorkQueue): Promise<void> {
   const batch = await queue.dequeue(BATCH_SIZE);
   if (batch.length === 0) {
+    const backoffMs = computeJitterBackoff(queue.backoffCount++);
+    await sleep(backoffMs);
     return pollNextBatch(queue);
   }
   await processBatch(batch);
 }`;
    } else if (traceText.includes('env-loader') || traceText.includes('DEVPULSE_APPROVAL_SECRET') || traceText.includes('config')) {
      file = 'src/config/env-loader.ts';
      line = 31;
      errorSignature = 'Error: DEVPULSE_APPROVAL_SECRET environment variable is missing.';
      rootCause = 'Strict config parser lacks staging/dev fallback handling for test secrets.';
      title = 'Configuration loader crash on missing HMAC secret';
      diff = `--- a/src/config/env-loader.ts
+++ b/src/config/env-loader.ts
@@ -29,3 +29,6 @@ export function loadGateSecret(): string {
   const secret = process.env['DEVPULSE_APPROVAL_SECRET'];
   if (!secret || secret.length < 32) {
+    if (process.env['NODE_ENV'] === 'development') {
+      return 'dev-ephemeral-test-secret-devpulse-32-chars-long';
+    }
     throw new Error('DEVPULSE_APPROVAL_SECRET is missing');
   }`;
    }

    const id = `INC-${Math.floor(8410 + Math.random() * 90)}`;
    const specHash = (await computeAuditHash('diff', 1, file, diff)).slice(0, 64);
    const challengeId = `appr_${id.toLowerCase()}_${Math.random().toString(36).slice(2, 6)}`;
    const now = Date.now();

    const matchedPrecedent = this.memoryRecords[0];

    const newIncident: Incident = {
      id,
      title,
      severity: 'critical',
      file,
      line,
      errorSignature,
      rootCause,
      stage: 5, // Challenge issued
      admittedAt: new Date(now).toISOString(),
      precedent: matchedPrecedent
        ? {
            id: matchedPrecedent.id,
            similarity: 92,
            fix: matchedPrecedent.fix,
            verified: matchedPrecedent.verified
          }
        : undefined,
      diff,
      specHash,
      challenge: {
        id: challengeId,
        expiresAt: new Date(now + 300000).toISOString(), // 5 minutes
        status: 'open'
      },
      sandbox: {
        flags: ['--network none', 'read-only rootfs', 'non-root: sandbox_user'],
        lines: [
          `[SANDBOX INIT] Enforcing isolation for incoming incident ${id}...`,
          '[SANDBOX INIT] Mounting isolated filesystem at /workspace/devpulse (read-only)...',
          '[SANDBOX INIT] Non-root UID 10001 configured.',
          '[SANDBOX INIT] Network namespace unshared (--network none active).',
          `[SENTINEL] Proposed patch generated (specHash: ${specHash.slice(0, 16)}...)`,
          `[SENTINEL] Issued 5-minute HMAC challenge ${challengeId}. Awaiting two-key turn.`
        ],
        exitCode: null,
        durationMs: 0
      }
    };

    this.incidents.unshift(newIncident);

    await this.appendAudit('INCIDENT_ADMITTED', {
      incidentId: id,
      culprit: `${file}:${line}`,
      errorSignature,
      specHash
    });

    await this.appendAudit('CHALLENGE_ISSUED', {
      incidentId: id,
      challengeId,
      ttlSeconds: 300,
      specHash
    });

    return newIncident;
  }

  public async submitApproval(req: ApprovalRequest): Promise<ApprovalResult> {
    const incident = this.incidents.find((i) => i.challenge?.id === req.challengeId);

    // Rule 1: Maintainer allowlist
    if (!ALLOWED_MAINTAINERS.includes(req.approverId)) {
      await this.appendAudit('APPROVAL_REJECTED', {
        challengeId: req.challengeId,
        approverId: req.approverId,
        reason: 'NOT_ON_ALLOWLIST',
        detail: `User '${req.approverId}' is not authorized in MAINTAINERS.txt.`
      });
      return {
        accepted: false,
        reason: `Maintainer allowlist violation: User '${req.approverId}' is not present in the cryptographic maintainers list. Authorization denied.`,
        code: 'NOT_ON_ALLOWLIST'
      };
    }

    // Rule 2: Bridged origin rejection (Slack / Discord)
    const normOrigin = req.origin.toLowerCase();
    if (normOrigin.includes('slack') || normOrigin.includes('discord') || normOrigin.includes('bridge')) {
      await this.appendAudit('INTRUDER_ORIGIN_BLOCKED', {
        challengeId: req.challengeId,
        approverId: req.approverId,
        origin: req.origin,
        reason: 'BRIDGED_ORIGIN',
        detail: `Attempted approval via bridged channel '${req.origin}'. Direct Switch Room origin strictly required.`
      });
      return {
        accepted: false,
        reason: `Bridged origin rejected: Approval attempted from '${req.origin}'. All approvals must originate directly inside an authorized Switch Console room to prevent webhook impersonation.`,
        code: 'BRIDGED_ORIGIN'
      };
    }

    // Rule 3: Single-use challenge (Replay attack detection)
    if (this.consumedChallenges.has(req.challengeId)) {
      await this.appendAudit('REPLAY_ATTACK_DETECTED', {
        challengeId: req.challengeId,
        approverId: req.approverId,
        reason: 'REPLAY_ATTACK',
        detail: `Challenge ID '${req.challengeId}' was already consumed in previous transaction.`
      });
      return {
        accepted: false,
        reason: `Replay attack detected: Challenge token '${req.challengeId}' has already been consumed. Challenges are strictly single-use.`,
        code: 'REPLAY_ATTACK'
      };
    }

    // Rule 4: 5-minute TTL check
    if (incident?.challenge) {
      const expiresAt = new Date(incident.challenge.expiresAt).getTime();
      if (Date.now() > expiresAt) {
        incident.challenge.status = 'expired';
        await this.appendAudit('APPROVAL_REJECTED', {
          challengeId: req.challengeId,
          approverId: req.approverId,
          reason: 'EXPIRED_TTL',
          detail: '5-minute HMAC challenge TTL has elapsed.'
        });
        return {
          accepted: false,
          reason: `Challenge expired: 5-minute HMAC TTL elapsed. Challenge '${req.challengeId}' is no longer valid. Sentinel must re-synthesize and issue a fresh challenge.`,
          code: 'EXPIRED_TTL'
        };
      }
    }

    // Rule 5: specHash binding check (diff tamper detection)
    if (req.specHash && incident && req.specHash !== incident.specHash) {
      await this.appendAudit('INTEGRITY_TAMPER_BLOCKED', {
        challengeId: req.challengeId,
        claimedSpecHash: req.specHash,
        targetSpecHash: incident.specHash,
        reason: 'HASH_MISMATCH'
      });
      return {
        accepted: false,
        reason: `Cryptographic hash mismatch: Submitted specHash (${req.specHash.slice(0, 16)}...) does not match Sentinel proposed specHash (${incident.specHash.slice(0, 16)}...). Patch content was modified.`,
        code: 'HASH_MISMATCH'
      };
    }

    // Approval Validated! Consume single-use challenge token atomically
    this.consumedChallenges.add(req.challengeId);
    if (incident?.challenge) {
      incident.challenge.status = 'consumed';
    }

    const executionId = `exec_${Math.random().toString(36).slice(2, 9)}`;

    await this.appendAudit('CHALLENGE_AUTHORIZED', {
      challengeId: req.challengeId,
      executionId,
      approverId: req.approverId,
      origin: req.origin,
      specHash: incident?.specHash
    });

    return {
      accepted: true,
      executionId
    };
  }

  public async runSandbox(
    incidentId: string,
    onLine: (line: string) => void
  ): Promise<{ exitCode: number; durationMs: number }> {
    const incident = this.incidents.find((i) => i.id === incidentId);
    if (!incident) {
      throw new Error(`Incident ${incidentId} not found`);
    }

    incident.stage = 8; // Stage 8: Execute
    const lines = [
      `[RUNNER] Isolation chamber engaged. Launching Docker sandbox (uid: 10001, net: none, rootfs: ro)...`,
      `[RUNNER] Applying approved patch (specHash: ${incident.specHash.slice(0, 16)}...)`,
      `[RUNNER] Patch applied cleanly to ${incident.file} (1 hunk)`,
      `[RUNNER] Executing verification test suite: npm test -- --runInBand`,
      `> test_session_handling ... ✔ PASS (18ms)`,
      `> test_null_token_graceful_rejection ... ✔ PASS (24ms)`,
      `> test_clock_skew_tolerance ... ✔ PASS (12ms)`,
      `[RUNNER] All tests passed (3/3). Exit code: 0.`
    ];

    if (!incident.sandbox) {
      incident.sandbox = {
        flags: ['--network none', 'read-only rootfs', 'non-root: sandbox_user'],
        lines: [],
        exitCode: null,
        durationMs: 0
      };
    }

    const start = Date.now();
    for (const line of lines) {
      await new Promise((res) => setTimeout(res, 220));
      incident.sandbox.lines.push(line);
      onLine(line);
    }

    const durationMs = Date.now() - start;
    incident.sandbox.exitCode = 0;
    incident.sandbox.durationMs = durationMs;
    incident.stage = 9; // Stage 9: Remember
    incident.resolvedAt = new Date().toISOString();

    await this.appendAudit('SANDBOX_EXECUTED', {
      incidentId,
      exitCode: 0,
      durationMs,
      sandboxFlags: incident.sandbox.flags
    });

    // Auto-record memory
    const newRecord = await this.recordMemory({
      signature: incident.errorSignature,
      rootCause: incident.rootCause,
      fix: `Verified fix in ${incident.file} with defensive guard.`,
      verified: true
    });

    await this.appendAudit('MEMORY_RECORDED', {
      incidentId,
      memoryRecordId: newRecord.id,
      verified: true
    });

    return { exitCode: 0, durationMs };
  }

  public async recordMemory(
    record: Omit<MemoryRecord, 'id' | 'createdAt'>
  ): Promise<MemoryRecord> {
    const id = `REC-${Math.floor(7400 + Math.random() * 600)}`;
    const newRecord: MemoryRecord = {
      ...record,
      id,
      createdAt: new Date().toISOString()
    };
    this.memoryRecords.unshift(newRecord);
    return newRecord;
  }

  public async verifyAuditChain(
    entries: AuditEntry[]
  ): Promise<{ valid: boolean; brokenSeq?: number; reason?: string }> {
    let prev = GENESIS_HASH;
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i]!;
      if (entry.prevHash !== prev) {
        return {
          valid: false,
          brokenSeq: entry.seq,
          reason: `Previous hash pointer mismatch at seq ${entry.seq}. Expected ${prev.slice(0, 16)}..., found ${entry.prevHash.slice(0, 16)}...`
        };
      }
      const computed = await computeAuditHash(entry.prevHash, entry.seq, entry.event, entry.detail);
      if (computed !== entry.hash) {
        return {
          valid: false,
          brokenSeq: entry.seq,
          reason: `Cryptographic digest mismatch at seq ${entry.seq}. Entry contents were altered.`
        };
      }
      prev = entry.hash;
    }
    return { valid: true };
  }
}

