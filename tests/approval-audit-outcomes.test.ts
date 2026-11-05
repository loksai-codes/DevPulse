import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promises as fs } from 'node:fs';

import { AuditLogger } from '../src/audit/audit-logger.js';
import { ChallengeTracker } from '../src/approval/challenge-tracker.js';
import { ApprovalHandler } from '../src/approval/approval-handler.js';
import { SentinelAgent } from '../src/sentinel/sentinel-agent.js';
import { RunnerAgent } from '../src/patch-runner/runner-agent.js';
import { SwitchAdapter } from '../src/room/switch-adapter.js';
import { EventRouter } from '../src/router/event-router.js';
import { NormalizedRoomEvent } from '../src/types/switch-protocol.js';

describe('Approval Audit Outcomes (Approved & Rejected Outcomes in Audit Trail)', () => {
  let testDir: string;
  let auditLogger: AuditLogger;
  let challengeTracker: ChallengeTracker;
  let approvalHandler: ApprovalHandler;

  const SECRET_KEY = 'test_approval_audit_secret_at_least_32_chars!';
  const MAINTAINERS = ['usr_alice_maintainer', 'usr_bob_reviewer'];
  const ROOM_ID = 'room_approval_audit_test';

  function createMockRoomEvent(overrides: Partial<NormalizedRoomEvent> = {}): NormalizedRoomEvent {
    return {
      eventId: `evt_${randomUUID().slice(0, 8)}`,
      roomId: ROOM_ID,
      senderId: 'usr_alice_maintainer',
      senderName: 'Alice Maintainer',
      senderType: 'USER',
      body: 'Approval command',
      isNativeConsole: true,
      bridgeId: null,
      addressedToMe: true,
      isSelfMessage: false,
      timestamp: Date.now(),
      raw: {},
      ...overrides
    };
  }

  beforeEach(async () => {
    testDir = join(tmpdir(), `devpulse-approval-audit-test-${randomUUID()}`);
    await fs.mkdir(testDir, { recursive: true });

    auditLogger = new AuditLogger({
      filePath: join(testDir, 'audit.jsonl'),
      secretKey: SECRET_KEY
    });
    await auditLogger.init();

    challengeTracker = new ChallengeTracker({
      persistenceFilePath: join(testDir, 'challenges.jsonl')
    });
    await challengeTracker.init();

    approvalHandler = new ApprovalHandler({
      maintainerAllowlist: MAINTAINERS,
      challengeTracker,
      auditLogger
    });
  });

  afterEach(async () => {
    await fs.rm(testDir, { recursive: true, force: true }).catch(() => {});
  });

  it('records approved outcome in audit trail when valid maintainer approves', async () => {
    const challenge = challengeTracker.createChallenge({
      specId: 'spec_audit_001',
      specHash: 'a'.repeat(64),
      allowedMaintainerIds: MAINTAINERS,
      ttlMs: 300000
    });

    const approvalEvent = createMockRoomEvent({
      senderId: 'usr_alice_maintainer',
      senderName: 'Alice Maintainer',
      senderType: 'USER',
      body: `@devpulse approve ${challenge.challengeId}`
    });

    const result = await approvalHandler.processApprovalCommand(approvalEvent, challenge.challengeId, {
      incidentId: 'INC-2026-TEST01',
      specId: 'spec_audit_001'
    });

    assert.equal(result.approved, true);
    assert.ok(result.challenge);
    assert.equal(result.challenge.consumed, true);

    const { entries } = await auditLogger.getEntries();
    assert.equal(entries.length, 1);

    const entry = entries[0]!;
    assert.equal(entry.action, 'HUMAN_APPROVAL_ACCEPTED');
    assert.equal(entry.actor.type, 'HUMAN');
    assert.equal(entry.actor.id, 'usr_alice_maintainer');
    assert.equal(entry.actor.name, 'Alice Maintainer');
    assert.equal(entry.specId, 'spec_audit_001');
    assert.equal(entry.incidentId, 'INC-2026-TEST01');

    assert.equal(entry.payload.outcome, 'approved');
    assert.equal(entry.payload.challengeId, challenge.challengeId);
    assert.equal(entry.payload.specHash, 'a'.repeat(64));
    assert.equal(entry.payload.actorId, 'usr_alice_maintainer');
    assert.equal(entry.payload.requesterId, 'usr_alice_maintainer');
    assert.ok(typeof entry.payload.timestamp === 'string');
    assert.ok(!Number.isNaN(Date.parse(entry.payload.timestamp as string)));

    const integrity = await auditLogger.verifyChainIntegrity();
    assert.equal(integrity.valid, true);
  });

  it('records rejected outcome in audit trail when unauthorized user attempts approval', async () => {
    const challenge = challengeTracker.createChallenge({
      specId: 'spec_audit_002',
      specHash: 'b'.repeat(64),
      allowedMaintainerIds: MAINTAINERS,
      ttlMs: 300000
    });

    const unauthorizedEvent = createMockRoomEvent({
      senderId: 'usr_mallory_outsider',
      senderName: 'Mallory Outsider',
      senderType: 'USER',
      body: `@devpulse approve ${challenge.challengeId}`
    });

    const result = await approvalHandler.processApprovalCommand(unauthorizedEvent, challenge.challengeId, {
      incidentId: 'INC-2026-TEST02'
    });

    assert.equal(result.approved, false);
    assert.match(result.reason!, /not in the authorized maintainer allowlist/);

    // Challenge remains unconsumed
    const stored = challengeTracker.getChallenge(challenge.challengeId);
    assert.equal(stored?.consumed, false);

    const { entries } = await auditLogger.getEntries();
    assert.equal(entries.length, 1);

    const entry = entries[0]!;
    assert.equal(entry.action, 'HUMAN_APPROVAL_REJECTED');
    assert.equal(entry.actor.id, 'usr_mallory_outsider');
    assert.equal(entry.actor.name, 'Mallory Outsider');

    assert.equal(entry.payload.outcome, 'rejected');
    assert.equal(entry.payload.challengeId, challenge.challengeId);
    assert.equal(entry.payload.actorId, 'usr_mallory_outsider');
    assert.equal(entry.payload.requesterId, 'usr_mallory_outsider');
    assert.match(entry.payload.reason as string, /not in the authorized maintainer allowlist/);
    assert.ok(typeof entry.payload.timestamp === 'string');

    const integrity = await auditLogger.verifyChainIntegrity();
    assert.equal(integrity.valid, true);
  });

  it('records rejected outcome when approval challenge has expired', async () => {
    const challenge = challengeTracker.createChallenge({
      specId: 'spec_audit_expired',
      specHash: 'c'.repeat(64),
      allowedMaintainerIds: MAINTAINERS,
      ttlMs: -1000 // Expired immediately
    });

    const event = createMockRoomEvent({
      senderId: 'usr_alice_maintainer',
      body: `@devpulse approve ${challenge.challengeId}`
    });

    const result = await approvalHandler.processApprovalCommand(event, challenge.challengeId);
    assert.equal(result.approved, false);
    assert.match(result.reason!, /expired/i);

    const { entries } = await auditLogger.getEntries();
    assert.equal(entries.length, 1);
    assert.equal(entries[0]!.action, 'HUMAN_APPROVAL_REJECTED');
    assert.equal(entries[0]!.payload.outcome, 'rejected');
    assert.match(entries[0]!.payload.reason as string, /expired/i);
    assert.equal(entries[0]!.payload.challengeId, challenge.challengeId);
  });

  it('records rejected outcome when replay attack is attempted on already-consumed challenge', async () => {
    const challenge = challengeTracker.createChallenge({
      specId: 'spec_audit_replay',
      specHash: 'd'.repeat(64),
      allowedMaintainerIds: MAINTAINERS,
      ttlMs: 300000
    });

    // 1st approval succeeds
    const firstEvent = createMockRoomEvent({
      eventId: 'evt_first_1',
      senderId: 'usr_alice_maintainer',
      body: `@devpulse approve ${challenge.challengeId}`
    });
    const firstResult = await approvalHandler.processApprovalCommand(firstEvent, challenge.challengeId);
    assert.equal(firstResult.approved, true);

    // 2nd approval attempt must fail and record rejection
    const secondEvent = createMockRoomEvent({
      eventId: 'evt_second_2',
      senderId: 'usr_alice_maintainer',
      body: `@devpulse approve ${challenge.challengeId}`
    });
    const secondResult = await approvalHandler.processApprovalCommand(secondEvent, challenge.challengeId);
    assert.equal(secondResult.approved, false);
    assert.match(secondResult.reason!, /Replay attack detected/);

    const { entries } = await auditLogger.getEntries();
    assert.equal(entries.length, 2);

    assert.equal(entries[0]!.action, 'HUMAN_APPROVAL_ACCEPTED');
    assert.equal(entries[0]!.payload.outcome, 'approved');

    assert.equal(entries[1]!.action, 'HUMAN_APPROVAL_REJECTED');
    assert.equal(entries[1]!.payload.outcome, 'rejected');
    assert.match(entries[1]!.payload.reason as string, /Replay attack detected/);

    const integrity = await auditLogger.verifyChainIntegrity();
    assert.equal(integrity.valid, true);
  });

  it('records rejected outcome when approval originates from external chat bridge', async () => {
    const challenge = challengeTracker.createChallenge({
      specId: 'spec_audit_bridge',
      specHash: 'e'.repeat(64),
      allowedMaintainerIds: MAINTAINERS,
      ttlMs: 300000
    });

    const bridgedEvent = createMockRoomEvent({
      senderId: 'usr_alice_maintainer',
      isNativeConsole: false,
      bridgeId: 'slack-bridge-ext',
      body: `@devpulse approve ${challenge.challengeId}`
    });

    const result = await approvalHandler.processApprovalCommand(bridgedEvent, challenge.challengeId);
    assert.equal(result.approved, false);
    assert.match(result.reason!, /external bridge/i);

    const { entries } = await auditLogger.getEntries();
    assert.equal(entries.length, 1);
    assert.equal(entries[0]!.action, 'HUMAN_APPROVAL_REJECTED');
    assert.equal(entries[0]!.payload.outcome, 'rejected');
    assert.match(entries[0]!.payload.reason as string, /external bridge/i);
  });

  it('records rejected outcome with SYSTEM actor type when untrusted bot attempts approval', async () => {
    const challenge = challengeTracker.createChallenge({
      specId: 'spec_audit_bot',
      specHash: 'f'.repeat(64),
      allowedMaintainerIds: MAINTAINERS,
      ttlMs: 300000
    });

    const botEvent = createMockRoomEvent({
      senderId: 'bot_automated_attacker',
      senderName: 'Automated Bot',
      senderType: 'BOT',
      body: `@devpulse approve ${challenge.challengeId}`
    });

    const result = await approvalHandler.processApprovalCommand(botEvent, challenge.challengeId);
    assert.equal(result.approved, false);
    assert.match(result.reason!, /Sender type 'BOT' is untrusted/);

    const { entries } = await auditLogger.getEntries();
    assert.equal(entries.length, 1);
    assert.equal(entries[0]!.action, 'HUMAN_APPROVAL_REJECTED');
    assert.equal(entries[0]!.actor.type, 'SYSTEM'); // Fallback ensures valid Zod schema enum
    assert.equal(entries[0]!.payload.outcome, 'rejected');
    assert.match(entries[0]!.payload.reason as string, /Sender type 'BOT' is untrusted/);
  });

  it('automatically connects auditLogger from EventRouter to ApprovalHandler', async () => {
    // Instantiate ApprovalHandler WITHOUT auditLogger
    const handlerWithoutLogger = new ApprovalHandler({
      maintainerAllowlist: MAINTAINERS,
      challengeTracker
    });
    assert.equal(handlerWithoutLogger.getAuditLogger(), undefined);

    const sentinel = new SentinelAgent({
      agentId: 'agn_sentinel_test',
      runnerAgentId: 'agn_runner_test',
      maintainerAllowlist: MAINTAINERS,
      challengeTracker
    });

    const runner = new RunnerAgent({
      agentId: 'agn_runner_test',
      sentinelAgentId: 'agn_sentinel_test',
      challengeTracker
    });

    const adapter = new SwitchAdapter({
      coreUrl: 'http://localhost:8080',
      agentId: 'agn_sentinel_test',
      apiKey: 'sw_test_key',
      roomId: ROOM_ID,
      reconnect: false,
      fetchFn: async () => new Response(JSON.stringify({ ok: true }), { status: 200 })
    });

    // EventRouter is initialized with auditLogger
    const router = new EventRouter({
      sentinel,
      runner,
      approvalHandler: handlerWithoutLogger,
      adapter,
      auditLogger,
      canonicalRepository: 'devpulse/core'
    });

    // Verification: EventRouter auto-wired its auditLogger to ApprovalHandler
    assert.equal(handlerWithoutLogger.getAuditLogger(), auditLogger);

    // Staging an incident
    const incidentEvent = createMockRoomEvent({
      senderId: 'usr_reporter',
      body: 'incident: TypeError in src/auth.js',
      addressedToMe: true
    });
    await router.routeEvent(incidentEvent);

    // Extract challenge ID from staged challenges
    const allChallenges = Array.from((challengeTracker as any).challenges.values()) as any[];
    assert.ok(allChallenges.length > 0);
    const challengeId = allChallenges[0].challengeId;

    // 1. Unauthorized attempt routed through EventRouter
    const unauthEvent = createMockRoomEvent({
      senderId: 'usr_stranger',
      senderName: 'Stranger',
      body: `@devpulse approve ${challengeId}`
    });
    const unauthResult = await router.routeEvent(unauthEvent);
    assert.equal(unauthResult.action, 'APPROVAL_REJECTED');

    // 2. Authorized attempt routed through EventRouter
    const authEvent = createMockRoomEvent({
      senderId: 'usr_alice_maintainer',
      senderName: 'Alice Maintainer',
      body: `@devpulse approve ${challengeId}`
    });
    const authResult = await router.routeEvent(authEvent);
    assert.equal(authResult.action, 'TASK_APPROVED_AND_QUEUED');

    // Verify audit log has both outcomes recorded
    const { entries } = await auditLogger.getEntries();
    const actions = entries.map((e) => e.action);

    assert.ok(actions.includes('HUMAN_APPROVAL_REJECTED'));
    assert.ok(actions.includes('HUMAN_APPROVAL_ACCEPTED'));

    const rejectedEntry = entries.find((e) => e.action === 'HUMAN_APPROVAL_REJECTED')!;
    assert.equal(rejectedEntry.payload.outcome, 'rejected');
    assert.equal(rejectedEntry.payload.actorId, 'usr_stranger');
    assert.equal(rejectedEntry.payload.challengeId, challengeId);

    const acceptedEntry = entries.find((e) => e.action === 'HUMAN_APPROVAL_ACCEPTED')!;
    assert.equal(acceptedEntry.payload.outcome, 'approved');
    assert.equal(acceptedEntry.payload.actorId, 'usr_alice_maintainer');
    assert.equal(acceptedEntry.payload.challengeId, challengeId);

    // Verify complete hash chain remains mathematically intact
    const chainVerification = await auditLogger.verifyChainIntegrity();
    assert.equal(chainVerification.valid, true);
  });
});
