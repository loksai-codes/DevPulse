import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { existsSync, unlinkSync } from 'node:fs';
import { EventRouter } from '../src/router/event-router.js';
import { SentinelAgent } from '../src/sentinel/sentinel-agent.js';
import { RunnerAgent } from '../src/patch-runner/runner-agent.js';
import { ApprovalHandler } from '../src/approval/approval-handler.js';
import { ChallengeTracker } from '../src/approval/challenge-tracker.js';
import { IdempotencyTracker } from '../src/router/idempotency.js';
import { SwitchAdapter } from '../src/room/switch-adapter.js';
import { NormalizedRoomEvent } from '../src/types/switch-protocol.js';

describe('EventRouter & Agent Orchestration (Stage 3 Integration)', () => {
  let challengeFile: string;
  let challengeTracker: ChallengeTracker;
  let sentinel: SentinelAgent;
  let runner: RunnerAgent;
  let approvalHandler: ApprovalHandler;
  let adapter: SwitchAdapter;
  let router: EventRouter;
  let postedMessages: string[] = [];

  const SENTINEL_ID = 'agn_sentinel_test';
  const RUNNER_ID = 'agn_runner_test';
  const MAINTAINERS = ['usr_alice_lead', 'usr_bob_reviewer'];
  const ROOM_ID = 'room_devpulse_ops';

  beforeEach(async () => {
    challengeFile = join(tmpdir(), `test-challenges-${randomUUID()}.jsonl`);
    challengeTracker = new ChallengeTracker({ persistenceFilePath: challengeFile });
    await challengeTracker.init();

    sentinel = new SentinelAgent({
      agentId: SENTINEL_ID,
      runnerAgentId: RUNNER_ID,
      maintainerAllowlist: MAINTAINERS,
      challengeTracker
    });

    runner = new RunnerAgent({
      agentId: RUNNER_ID,
      sentinelAgentId: SENTINEL_ID
    });

    approvalHandler = new ApprovalHandler({
      maintainerAllowlist: MAINTAINERS,
      challengeTracker
    });

    postedMessages = [];
    adapter = new SwitchAdapter({
      coreUrl: 'http://localhost:8080',
      agentId: SENTINEL_ID,
      apiKey: 'sw_test_key_123',
      roomId: ROOM_ID,
      reconnect: false,
      fetchFn: async (_url, init) => {
        if (init && init.body) {
          try {
            const parsed = JSON.parse(init.body as string);
            if (parsed.content) {
              postedMessages.push(parsed.content);
            }
          } catch {}
        }
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
    });

    router = new EventRouter({
      sentinel,
      runner,
      approvalHandler,
      adapter,
      idempotencyTracker: new IdempotencyTracker()
    });
  });

  afterEach(() => {
    if (existsSync(challengeFile)) {
      try {
        unlinkSync(challengeFile);
      } catch {}
    }
  });

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
      addressedToMe: false,
      isSelfMessage: false,
      timestamp: Date.now(),
      raw: {},
      ...overrides
    };
  }

  it('routes incident report -> Sentinel investigates -> Risk Report computed -> approval challenge emitted', async () => {
    const event = createMockRoomEvent({
      senderId: 'usr_dev_charlie',
      body: 'incident: TypeError: Cannot read properties of undefined in src/auth.ts',
      addressedToMe: true
    });

    let investigationCaptured: any = null;
    router.on('investigation_completed', (result) => {
      investigationCaptured = result;
    });

    const routeResult = await router.routeEvent(event);

    assert.equal(routeResult.handled, true);
    assert.equal(routeResult.action, 'INCIDENT_INVESTIGATED');
    assert.ok(investigationCaptured);
    assert.ok(investigationCaptured.challenge.challengeId.startsWith('appr_'));
    assert.equal(investigationCaptured.riskReport.riskScore, 12);
    assert.equal(investigationCaptured.riskReport.riskLevel, 'LOW');
    assert.equal(investigationCaptured.spec.status, 'PROPOSED');

    // Proves formatted report and mandatory approval instructions were posted to room
    assert.equal(postedMessages.length, 1);
    assert.match(postedMessages[0]!, /Incident Investigation Report/);
    assert.match(postedMessages[0]!, /Mandatory Human-in-the-Loop Approval Required/);
    assert.match(postedMessages[0]!, new RegExp(investigationCaptured.challenge.challengeId));
  });

  it('executes human approval workflow: verified maintainer approves -> challenge consumed -> task dispatched to Runner', async () => {
    // 1. Trigger incident to stage specification
    const incidentEvent = createMockRoomEvent({
      senderId: 'usr_dev_charlie',
      body: 'incident: TypeError in src/session.ts',
      addressedToMe: true
    });
    await router.routeEvent(incidentEvent);

    const promptMessage = postedMessages[0]!;
    const match = promptMessage.match(/appr_[a-f0-9]{8}/);
    assert.ok(match, 'Prompt must contain approval challenge ID');
    const challengeId = match[0]!;

    // 2. Maintainer Alice in native Switch Console issues approval command
    const approvalEvent = createMockRoomEvent({
      senderId: 'usr_alice_lead',
      senderName: 'Alice',
      body: `@devpulse approve ${challengeId}`,
      isNativeConsole: true,
      bridgeId: null
    });

    let dispatchedTask: any = null;
    router.on('task_dispatched', (data) => {
      dispatchedTask = data;
    });

    const approvalResult = await router.routeEvent(approvalEvent);

    assert.equal(approvalResult.handled, true);
    assert.equal(approvalResult.action, 'TASK_APPROVED_AND_QUEUED');

    assert.ok(dispatchedTask);
    assert.equal(dispatchedTask.taskRequest.type, 'TASK_REQUEST');
    assert.equal(dispatchedTask.taskRequest.senderAgentId, SENTINEL_ID);
    assert.equal(dispatchedTask.taskRequest.targetAgentId, RUNNER_ID);
    assert.equal(dispatchedTask.taskRequest.hopCount, 1);
    assert.equal(dispatchedTask.taskRequest.approvedBy, 'usr_alice_lead');
    assert.equal(dispatchedTask.runnerResult.accepted, true);
    assert.equal(dispatchedTask.runnerResult.response?.status, 'QUEUED');

    // Verify challenge is marked consumed in tracker
    const challenge = challengeTracker.getChallenge(challengeId);
    assert.equal(challenge?.consumed, true);
    assert.equal(challenge?.consumedBy, 'usr_alice_lead');
  });

  it('rejects approval originating from external chat bridge (Slack/Discord)', async () => {
    // 1. Stage specification
    await router.routeEvent(createMockRoomEvent({
      body: 'incident: TypeError in src/auth.ts',
      addressedToMe: true
    }));
    const challengeId = postedMessages[0]!.match(/appr_[a-f0-9]{8}/)![0]!;

    // 2. Attempt approval from bridged Slack session
    const bridgedEvent = createMockRoomEvent({
      senderId: 'usr_alice_lead',
      body: `@devpulse approve ${challengeId}`,
      isNativeConsole: false,
      bridgeId: 'slack-bridge-01'
    });

    const routeResult = await router.routeEvent(bridgedEvent);

    assert.equal(routeResult.handled, true);
    assert.equal(routeResult.action, 'APPROVAL_REJECTED');
    assert.match(routeResult.reason!, /Originates from external bridge/);

    // Challenge must remain unconsumed
    const challenge = challengeTracker.getChallenge(challengeId);
    assert.equal(challenge?.consumed, false);
  });

  it('rejects approval from non-allowlisted human user', async () => {
    // 1. Stage specification
    await router.routeEvent(createMockRoomEvent({
      body: 'incident: TypeError in src/auth.ts',
      addressedToMe: true
    }));
    const challengeId = postedMessages[0]!.match(/appr_[a-f0-9]{8}/)![0]!;

    // 2. Unauthorized user attempts approval
    const unauthorizedEvent = createMockRoomEvent({
      senderId: 'usr_mallory_unauthorized',
      body: `@devpulse approve ${challengeId}`,
      isNativeConsole: true,
      bridgeId: null
    });

    const routeResult = await router.routeEvent(unauthorizedEvent);

    assert.equal(routeResult.handled, true);
    assert.equal(routeResult.action, 'APPROVAL_REJECTED');
    assert.match(routeResult.reason!, /not in the authorized maintainer allowlist/);

    // Challenge must remain unconsumed
    const challenge = challengeTracker.getChallenge(challengeId);
    assert.equal(challenge?.consumed, false);
  });

  it('prevents replay attacks on consumed approval challenges', async () => {
    // 1. Stage specification
    await router.routeEvent(createMockRoomEvent({
      body: 'incident: TypeError in src/auth.ts',
      addressedToMe: true
    }));
    const challengeId = postedMessages[0]!.match(/appr_[a-f0-9]{8}/)![0]!;

    // 2. First approval succeeds
    const firstApproval = createMockRoomEvent({
      eventId: 'evt_appr_1',
      senderId: 'usr_alice_lead',
      body: `@devpulse approve ${challengeId}`
    });
    const firstResult = await router.routeEvent(firstApproval);
    assert.equal(firstResult.action, 'TASK_APPROVED_AND_QUEUED');

    // 3. Second approval attempt with same challenge ID is rejected
    const replayApproval = createMockRoomEvent({
      eventId: 'evt_appr_2',
      senderId: 'usr_alice_lead',
      body: `@devpulse approve ${challengeId}`
    });
    const replayResult = await router.routeEvent(replayApproval);

    assert.equal(replayResult.handled, true);
    assert.equal(replayResult.action, 'APPROVAL_REJECTED');
    assert.match(replayResult.reason!, /Replay attack detected/);
  });

  it('Runner rejects task requests from untrusted agent identities', async () => {
    const forgedTaskRequest = {
      id: randomUUID(),
      type: 'TASK_REQUEST',
      correlationId: randomUUID(),
      timestamp: new Date().toISOString(),
      senderAgentId: 'agn_attacker_fake_sentinel', // Spoofed identity!
      targetAgentId: RUNNER_ID,
      hopCount: 1,
      spec: {
        id: 'spec_fake',
        incidentId: 'INC-999999',
        createdAt: new Date().toISOString(),
        targetRepository: 'owner/devpulse-demo',
        baseBranch: 'main',
        targetBranch: 'devpulse/fix-fake',
        errorSignature: 'Error',
        rootCause: 'Cause',
        patches: [{ path: 'src/auth.ts', action: 'MODIFY', patchDiff: 'diff' }],
        diffHash: 'a'.repeat(64),
        riskReport: {
          riskScore: 10,
          riskLevel: 'LOW',
          blastRadius: ['src/auth.ts'],
          testsImpacted: [],
          rollbackStrategy: 'revert',
          safetyGuarantees: []
        },
        verificationCommands: ['npm test'],
        status: 'PROPOSED',
        specHash: 'b'.repeat(64)
      },
      challengeId: 'appr_fake1234',
      approvedBy: 'usr_alice_lead',
      approvedAt: new Date().toISOString()
    };

    const peerMessageEvent = createMockRoomEvent({
      senderId: 'agn_attacker_fake_sentinel',
      body: JSON.stringify(forgedTaskRequest)
    });

    const routeResult = await router.routeEvent(peerMessageEvent);
    assert.equal(routeResult.handled, true);
    assert.equal(routeResult.action, 'RUNNER_TASK_PROCESSED');

    // Runner must reply with rejection
    const lastPosted = postedMessages[postedMessages.length - 1]!;
    assert.match(lastPosted, /TASK_REQUEST REJECTED/);
    assert.match(lastPosted, /Sender 'agn_attacker_fake_sentinel' is not the authorized Sentinel/);
  });

  it('drops duplicate events via idempotency tracker', async () => {
    const duplicateEvent = createMockRoomEvent({
      eventId: 'evt_exact_duplicate_123',
      body: 'incident: Exception in src/auth.ts',
      addressedToMe: true
    });

    // 1st delivery processed
    const first = await router.routeEvent(duplicateEvent);
    assert.equal(first.handled, true);

    // 2nd delivery with identical eventId dropped
    const second = await router.routeEvent(duplicateEvent);
    assert.equal(second.handled, false);
    assert.match(second.reason!, /Duplicate event 'evt_exact_duplicate_123' dropped/);
  });

  it('drops self-messages emitted by DevPulse agents to avoid message loops', async () => {
    const selfMessage = createMockRoomEvent({
      senderId: SENTINEL_ID,
      isSelfMessage: true,
      body: 'Autonomous announcement'
    });

    const result = await router.routeEvent(selfMessage);
    assert.equal(result.handled, false);
    assert.match(result.reason!, /Self-message dropped to prevent infinite loops/);
  });

  it('rejects structured agent messages exceeding hop count limit (> 2)', async () => {
    const invalidHopMessage = {
      id: randomUUID(),
      type: 'TASK_REQUEST',
      correlationId: randomUUID(),
      timestamp: new Date().toISOString(),
      senderAgentId: SENTINEL_ID,
      targetAgentId: RUNNER_ID,
      hopCount: 3, // Exceeds max depth of 2!
      spec: {
        id: 'spec_deep',
        incidentId: 'INC-777777',
        createdAt: new Date().toISOString(),
        targetRepository: 'owner/devpulse-demo',
        baseBranch: 'main',
        targetBranch: 'devpulse/fix-deep',
        errorSignature: 'Error',
        rootCause: 'Cause',
        patches: [{ path: 'src/auth.ts', action: 'MODIFY', patchDiff: 'diff' }],
        diffHash: 'a'.repeat(64),
        riskReport: {
          riskScore: 10,
          riskLevel: 'LOW',
          blastRadius: ['src/auth.ts'],
          testsImpacted: [],
          rollbackStrategy: 'revert',
          safetyGuarantees: []
        },
        verificationCommands: ['npm test'],
        status: 'PROPOSED',
        specHash: 'b'.repeat(64)
      },
      challengeId: 'appr_deep1234',
      approvedBy: 'usr_alice_lead',
      approvedAt: new Date().toISOString()
    };

    const peerMessageEvent = createMockRoomEvent({
      senderId: SENTINEL_ID,
      body: JSON.stringify(invalidHopMessage)
    });

    const routeResult = await router.routeEvent(peerMessageEvent);
    assert.equal(routeResult.handled, false);
    assert.match(routeResult.reason!, /Malformed structured agent message/);
  });
});
