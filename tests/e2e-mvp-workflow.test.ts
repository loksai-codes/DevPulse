import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';

import { AuditLogger } from '../src/audit/audit-logger.js';
import { ChallengeTracker } from '../src/approval/challenge-tracker.js';
import { ApprovalHandler } from '../src/approval/approval-handler.js';
import { IncidentStore } from '../src/memory/incident-store.js';
import { IncidentMemoryRecord } from '../src/memory/types.js';
import { SentinelAgent } from '../src/sentinel/sentinel-agent.js';
import { RunnerAgent } from '../src/patch-runner/runner-agent.js';
import { ContainerSandboxDriver } from '../src/patch-runner/sandbox-driver.js';
import { EventRouter } from '../src/router/event-router.js';
import { SwitchAdapter } from '../src/room/switch-adapter.js';
import { NormalizedRoomEvent } from '../src/types/switch-protocol.js';

describe('DevPulse End-to-End MVP: Complete 9-Step Autonomous Incident Triage Workflow', () => {
  const TEST_DIR = path.resolve(tmpdir(), `devpulse-e2e-${randomUUID().slice(0, 8)}`);
  const SAMPLE_REPO_PATH = path.resolve('tests/fixtures/sample-repo');
  const MAINTAINERS = ['usr_alice_lead', 'usr_bob_reviewer'];
  const ROOM_ID = 'room_devpulse_ops';
  const SENTINEL_ID = 'agt_sentinel_01';
  const RUNNER_ID = 'agt_runner_01';

  let auditFile: string;
  let challengeFile: string;
  let jsonlFile: string;
  let mdFile: string;
  let quarFile: string;

  let auditLogger: AuditLogger;
  let challengeTracker: ChallengeTracker;
  let incidentStore: IncidentStore;
  let sentinel: SentinelAgent;
  let runner: RunnerAgent;
  let approvalHandler: ApprovalHandler;
  let adapter: SwitchAdapter;
  let router: EventRouter;
  let sandboxDriver: ContainerSandboxDriver;

  const roomMessagesSent: Array<{ body: string; threadId?: string; roomId?: string }> = [];

  function createMockRoomEvent(overrides: Partial<NormalizedRoomEvent> = {}): NormalizedRoomEvent {
    return {
      eventId: `evt_${randomUUID().slice(0, 8)}`,
      roomId: ROOM_ID,
      senderId: 'usr_alice_lead',
      senderName: 'Alice',
      senderType: 'USER',
      body: 'Hello room',
      isNativeConsole: true,
      bridgeId: null,
      addressedToMe: true,
      isSelfMessage: false,
      timestamp: Date.now(),
      raw: {},
      ...overrides
    };
  }

  before(async () => {
    await fs.mkdir(TEST_DIR, { recursive: true });
    auditFile = path.join(TEST_DIR, 'audit.jsonl');
    challengeFile = path.join(TEST_DIR, 'challenges.jsonl');
    jsonlFile = path.join(TEST_DIR, 'incidents.jsonl');
    mdFile = path.join(TEST_DIR, 'incidents.md');
    quarFile = path.join(TEST_DIR, 'quarantine.jsonl');

    // 1. Initialize Audit Logger
    auditLogger = new AuditLogger({
      filePath: auditFile,
      secretKey: 'test_secure_hmac_secret_key_32_chars_min'
    });
    await auditLogger.init();

    // 2. Initialize Challenge Tracker
    challengeTracker = new ChallengeTracker({
      persistenceFilePath: challengeFile
    });
    await challengeTracker.init();

    // 3. Initialize Incident Store with past precedent intelligence
    incidentStore = new IncidentStore({
      jsonlPath: jsonlFile,
      markdownPath: mdFile,
      quarantinePath: quarFile
    });
    await incidentStore.init();

    // Seed past similar incident in memory
    const pastIncident: IncidentMemoryRecord = {
      id: 'INC-2026-PAST01',
      canonicalRepository: 'devpulse/core',
      timestamp: '2026-11-04T10:00:00.000Z',
      category: 'RUNTIME_EXCEPTION',
      affectedTarget: 'src/auth.js',
      errorSignature: "TypeError: Cannot read properties of null (reading 'expiresAt')",
      rootCause: 'Null dereference in session token object',
      fixSummary: 'Guard token dereference with optional chaining and fallback',
      diffHash: 'a'.repeat(64),
      prLink: 'https://github.com/devpulse/core/pull/88',
      outcome: 'RESOLVED',
      verificationStatus: 'VERIFIED_RESOLVED',
      resolutionHistory: []
    };
    await incidentStore.append(pastIncident);

    // 4. Initialize Container Sandbox Driver (Real Docker Container)
    sandboxDriver = new ContainerSandboxDriver({
      runtimeBinary: 'docker',
      defaultImage: 'node:20-alpine',
      defaultTimeoutMs: 30000
    });

    // 5. Initialize Sentinel Agent
    sentinel = new SentinelAgent({
      agentId: SENTINEL_ID,
      runnerAgentId: RUNNER_ID,
      maintainerAllowlist: MAINTAINERS,
      challengeTracker,
      auditLogger,
      incidentStore,
      defaultCanonicalRepository: 'devpulse/core'
    });

    // 6. Initialize Runner Agent connected to Hardened Container Sandbox
    runner = new RunnerAgent({
      agentId: RUNNER_ID,
      sentinelAgentId: SENTINEL_ID,
      challengeTracker,
      auditLogger,
      sandboxDriver,
      sampleRepoTemplatePath: SAMPLE_REPO_PATH,
      sandboxImage: 'node:20-alpine'
    });

    // 7. Initialize Approval Handler
    approvalHandler = new ApprovalHandler({
      maintainerAllowlist: MAINTAINERS,
      challengeTracker
    });

    // 8. Initialize Switch Adapter (mock room sender)
    adapter = new SwitchAdapter({
      coreUrl: 'http://localhost:8080',
      agentId: SENTINEL_ID,
      apiKey: 'sw_test_key_e2e',
      roomId: ROOM_ID
    });

    // Intercept outbound room messages for verification
    adapter.sendMessage = async (body: string, threadId?: string, roomId?: string) => {
      roomMessagesSent.push({ body, threadId, roomId });
      return { success: true, messageId: `msg_${randomUUID()}` };
    };

    // 9. Initialize Event Router
    router = new EventRouter({
      adapter,
      sentinel,
      runner,
      approvalHandler,
      auditLogger,
      canonicalRepository: 'devpulse/core'
    });
  });

  after(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true }).catch(() => {});
  });

  it('executes the complete 9-step incident triage workflow through real Docker sandbox execution', async () => {
    // -----------------------------------------------------------------------
    // STEP 1 & 2: Incident Enters Through Switch Console & Sentinel Investigates
    // -----------------------------------------------------------------------
    const traceBody = [
      "incident: TypeError: Cannot read properties of null (reading 'expiresAt')",
      '    at getSessionExpiration (src/auth.js:24:12)',
      '    at handleRequest (src/server.js:88:9)'
    ].join('\n');

    const incidentEvent = createMockRoomEvent({
      senderId: 'usr_monitor_bot',
      senderName: 'Datadog Alert Bridge',
      body: traceBody
    });

    const investigationResult = await router.routeEvent(incidentEvent);
    assert.equal(investigationResult.handled, true);
    assert.equal(investigationResult.action, 'INCIDENT_INVESTIGATED');

    // Verify Sentinel posted investigation report to Switch room
    assert.ok(roomMessagesSent.length >= 1);
    const sentinelReport = roomMessagesSent[0]!.body;
    assert.ok(sentinelReport.includes('### 🔍 [SENTINEL] Incident Investigation Report'));
    assert.ok(sentinelReport.includes('Root Cause:'));
    assert.ok(sentinelReport.includes('src/auth.js'));
    assert.ok(sentinelReport.includes('Historical Precedents'));
    assert.ok(sentinelReport.includes('INC-2026-PAST01')); // Memory intelligence retrieved!
    assert.ok(sentinelReport.includes('@devpulse approve')); // HITL challenge instruction emitted!

    // Extract challenge ID from the sentinel report in room
    const match = sentinelReport.match(/appr_[a-f0-9]+/);
    assert.ok(match, 'Sentinel report must contain @devpulse approve appr_... prompt');
    const challengeId = match[0]!;

    // -----------------------------------------------------------------------
    // STEP 3: Security Gate - Unauthorized Approval Rejection
    // -----------------------------------------------------------------------
    const unauthorizedEvent = createMockRoomEvent({
      senderId: 'usr_unauthorized_attacker',
      senderName: 'Mallory',
      body: `@devpulse approve ${challengeId}`
    });

    const unauthResult = await router.routeEvent(unauthorizedEvent);
    assert.equal(unauthResult.action, 'APPROVAL_REJECTED');
    assert.equal(challengeTracker.getChallenge(challengeId)?.consumed, false);

    // -----------------------------------------------------------------------
    // STEP 4 & 5: Authorized Human Maintainer Approves in Switch Console
    // -----------------------------------------------------------------------
    const authorizedApprovalEvent = createMockRoomEvent({
      senderId: 'usr_alice_lead', // Maintainer in allowlist
      senderName: 'Alice Engineering Lead',
      body: `@devpulse approve ${challengeId}`
    });

    // -----------------------------------------------------------------------
    // STEP 6, 7 & 8: Runner Receives Task, Applies Patch, Runs Real Container Tests
    // -----------------------------------------------------------------------
    const executionResult = await router.routeEvent(authorizedApprovalEvent);
    assert.equal(executionResult.handled, true);
    assert.equal(executionResult.action, 'TASK_APPROVED_AND_EXECUTED');

    // Verify challenge is atomically consumed
    assert.equal(challengeTracker.getChallenge(challengeId)?.consumed, true);
    assert.equal(challengeTracker.getChallenge(challengeId)?.consumedBy, 'usr_alice_lead');

    // -----------------------------------------------------------------------
    // STEP 9: Review Complete Execution Evidence Reported to Switch Room
    // -----------------------------------------------------------------------
    // Look at the latest message sent to the room
    const latestRoomMessage = roomMessagesSent[roomMessagesSent.length - 1]!.body;

    assert.ok(latestRoomMessage.includes('PATCH & TEST RUNNER'));
    assert.ok(latestRoomMessage.includes('Execution PASSED ✅'));
    assert.ok(latestRoomMessage.includes('`0`'));
    assert.ok(latestRoomMessage.includes('Hardened Container'));
    assert.ok(latestRoomMessage.includes('--network none'));
    assert.ok(latestRoomMessage.includes('PASS: All auth session verification tests passed cleanly (2/2).'));

    // -----------------------------------------------------------------------
    // STEP 10: Verify Tamper-Evident Audit Trail Integrity
    // -----------------------------------------------------------------------
    const verification = await auditLogger.verifyChainIntegrity();
    assert.equal(verification.valid, true, 'Audit log chain must be mathematically intact');

    const logRes = await auditLogger.getEntries();
    assert.ok(logRes.entries.length >= 3, 'Must record security-relevant events');
    const actions = logRes.entries.map((e) => e.action);
    assert.ok(actions.includes('INVESTIGATION_COMPLETED'));
    assert.ok(actions.includes('TASK_EXECUTION_COMPLETED'));
  });
});
