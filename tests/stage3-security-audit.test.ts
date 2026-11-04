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
import { TaskRequestMessage } from '../src/types/agent-contracts.js';
import { computeDiffHash, computeSpecHash } from '../src/utils/crypto.js';

describe('Stage 3 Final Security Audit: Human Identity, Atomic Consumption & Runner Verification', () => {
  let challengeFile: string;
  let challengeTracker: ChallengeTracker;
  let sentinel: SentinelAgent;
  let runner: RunnerAgent;
  let approvalHandler: ApprovalHandler;
  let adapter: SwitchAdapter;
  let router: EventRouter;

  const SENTINEL_ID = 'agn_sentinel_audit';
  const RUNNER_ID = 'agn_runner_audit';
  const MAINTAINERS = ['usr_alice_lead', 'usr_bob_reviewer'];
  const ROOM_ID = 'room_devpulse_ops';

  beforeEach(async () => {
    challengeFile = join(tmpdir(), `audit-challenges-${randomUUID()}.jsonl`);
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
      sentinelAgentId: SENTINEL_ID,
      challengeTracker
    });

    approvalHandler = new ApprovalHandler({
      maintainerAllowlist: MAINTAINERS,
      challengeTracker
    });

    adapter = new SwitchAdapter({
      coreUrl: 'http://localhost:8080',
      agentId: SENTINEL_ID,
      apiKey: 'sw_test_key_audit',
      roomId: ROOM_ID,
      reconnect: false,
      fetchFn: async () => new Response(JSON.stringify({ ok: true }), { status: 200 })
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
      try { unlinkSync(challengeFile); } catch {}
    }
  });

  function createMockRoomEvent(overrides: Partial<NormalizedRoomEvent> = {}): NormalizedRoomEvent {
    return {
      eventId: `evt_${randomUUID().slice(0, 8)}`,
      sequence: 1,
      roomId: ROOM_ID,
      senderId: 'usr_alice_lead',
      senderName: 'Alice',
      senderType: 'USER',
      body: 'Hello',
      isNativeConsole: true,
      bridgeId: null,
      channelType: null,
      addressedToMe: false,
      isSelfMessage: false,
      timestamp: Date.now(),
      threadId: null,
      raw: {},
      ...overrides
    };
  }

  // =========================================================================
  // 1. HUMAN IDENTITY VERIFICATION
  // =========================================================================
  describe('1. Human Identity Verification & Origin Filtering', () => {
    it('proves bridge_id === null is strictly an origin filter and does NOT grant automatic authorization', async () => {
      // Stage an incident specification
      const staged = await sentinel.investigate({
        rawText: 'incident: TypeError in src/auth.ts',
        senderId: 'usr_charlie',
        roomId: ROOM_ID
      });

      // An unauthorized user in native Switch console (bridge_id === null) attempts approval
      const event = createMockRoomEvent({
        senderId: 'usr_unauthorized_attacker',
        senderName: 'Attacker',
        body: `@devpulse approve ${staged.challenge.challengeId}`,
        isNativeConsole: true,
        bridgeId: null
      });

      const result = await approvalHandler.processApprovalCommand(event, staged.challenge.challengeId);
      assert.equal(result.approved, false);
      assert.match(result.reason!, /not in the authorized maintainer allowlist/);

      // Challenge must remain unconsumed
      const challenge = challengeTracker.getChallenge(staged.challenge.challengeId);
      assert.equal(challenge?.consumed, false);
    });

    it('rejects approval if senderType is BOT or AGENT, even if claiming an allowlisted ID', async () => {
      const staged = await sentinel.investigate({
        rawText: 'incident: TypeError in src/auth.ts',
        senderId: 'usr_charlie',
        roomId: ROOM_ID
      });

      const botEvent = createMockRoomEvent({
        senderId: 'usr_alice_lead',
        senderName: 'Alice Puppet Bot',
        senderType: 'BOT',
        body: `@devpulse approve ${staged.challenge.challengeId}`
      });

      const result = await approvalHandler.processApprovalCommand(botEvent, staged.challenge.challengeId);
      assert.equal(result.approved, false);
      assert.match(result.reason!, /Sender type 'BOT' is untrusted or missing/);

      const challenge = challengeTracker.getChallenge(staged.challenge.challengeId);
      assert.equal(challenge?.consumed, false);
    });

    it('rejects external bridged chat origins (Slack, Discord, Teams) even from allowlisted names', async () => {
      const staged = await sentinel.investigate({
        rawText: 'incident: TypeError in src/auth.ts',
        senderId: 'usr_charlie',
        roomId: ROOM_ID
      });

      const bridgedEvent = createMockRoomEvent({
        senderId: 'usr_alice_lead',
        senderName: 'Alice',
        isNativeConsole: false,
        bridgeId: 'slack-production-bridge',
        body: `@devpulse approve ${staged.challenge.challengeId}`
      });

      const result = await approvalHandler.processApprovalCommand(bridgedEvent, staged.challenge.challengeId);
      assert.equal(result.approved, false);
      assert.match(result.reason!, /Originates from external bridge 'slack-production-bridge'/);

      const challenge = challengeTracker.getChallenge(staged.challenge.challengeId);
      assert.equal(challenge?.consumed, false);
    });

    it('ignores client-injected sender strings inside message body, strictly taking sender from server metadata', async () => {
      const staged = await sentinel.investigate({
        rawText: 'incident: TypeError in src/auth.ts',
        senderId: 'usr_charlie',
        roomId: ROOM_ID
      });

      // Mallory claims in the text: "sender: usr_alice_lead"
      const spoofAttemptEvent = createMockRoomEvent({
        senderId: 'usr_mallory_attacker',
        senderName: 'Mallory',
        body: `@devpulse approve ${staged.challenge.challengeId} sender:usr_alice_lead approver:usr_alice_lead`
      });

      const result = await approvalHandler.processApprovalCommand(spoofAttemptEvent, staged.challenge.challengeId);
      assert.equal(result.approved, false);
      assert.match(result.reason!, /User 'usr_mallory_attacker' .* not in the authorized maintainer allowlist/);

      const challenge = challengeTracker.getChallenge(staged.challenge.challengeId);
      assert.equal(challenge?.consumed, false);
    });

    it('rejects approval if senderType is missing or undefined, enforcing safe default for unverified Switch payloads', async () => {
      const staged = await sentinel.investigate({
        rawText: 'incident: TypeError in src/auth.ts',
        senderId: 'usr_charlie',
        roomId: ROOM_ID
      });

      const untypedEvent = createMockRoomEvent({
        senderId: 'usr_alice_lead',
        senderName: 'Alice',
        senderType: undefined, // Missing from Switch event frame!
        body: `@devpulse approve ${staged.challenge.challengeId}`
      });

      const result = await approvalHandler.processApprovalCommand(untypedEvent, staged.challenge.challengeId);
      assert.equal(result.approved, false);
      assert.match(result.reason!, /Sender type 'MISSING' is untrusted or missing/);

      const challenge = challengeTracker.getChallenge(staged.challenge.challengeId);
      assert.equal(challenge?.consumed, false);
    });
  });

  // =========================================================================
  // 2. ATOMIC APPROVAL CONSUMPTION & CONCURRENCY
  // =========================================================================
  describe('2. Atomic Approval Consumption & Concurrency', () => {
    it('executes two simultaneous approval requests for the same challenge ID: exactly one succeeds and one fails', async () => {
      // 1. Stage an incident specification through router
      await router.routeEvent(createMockRoomEvent({
        body: 'incident: TypeError in src/auth.ts',
        addressedToMe: true
      }));

      // Find challenge ID from tracker
      let stagedChallengeId = '';
      for (const [id] of (challengeTracker as any).challenges) {
        stagedChallengeId = id;
      }
      assert.ok(stagedChallengeId, 'Challenge must be registered');

      // 2. Fire two simultaneous approval requests with distinct event IDs
      const event1 = createMockRoomEvent({
        eventId: 'evt_simultaneous_1',
        senderId: 'usr_alice_lead',
        body: `@devpulse approve ${stagedChallengeId}`
      });

      const event2 = createMockRoomEvent({
        eventId: 'evt_simultaneous_2',
        senderId: 'usr_bob_reviewer',
        body: `@devpulse approve ${stagedChallengeId}`
      });

      const [res1, res2] = await Promise.all([
        router.routeEvent(event1),
        router.routeEvent(event2)
      ]);

      const successCount = [res1, res2].filter((r) => r.action === 'TASK_APPROVED_AND_QUEUED').length;
      const replayCount = [res1, res2].filter((r) => r.action === 'APPROVAL_REJECTED' && r.reason?.includes('Replay attack detected')).length;

      assert.equal(successCount, 1, 'Exactly one approval must succeed');
      assert.equal(replayCount, 1, 'Exactly one approval must be rejected as a replay attempt');

      // Verify challenge is marked consumed exactly once
      const challenge = challengeTracker.getChallenge(stagedChallengeId);
      assert.equal(challenge?.consumed, true);
    });

    it('survives high concurrency: 10 parallel calls to consumeChallenge result in exactly 1 success and 9 replay rejections', async () => {
      const challenge = challengeTracker.createChallenge({
        specId: 'spec_concurrent',
        specHash: 'c'.repeat(64),
        allowedMaintainerIds: MAINTAINERS
      });

      const promises = Array.from({ length: 10 }, (_, i) =>
        Promise.resolve().then(() =>
          challengeTracker.consumeChallenge(challenge.challengeId, MAINTAINERS[i % MAINTAINERS.length]!)
        )
      );

      const results = await Promise.all(promises);
      const successes = results.filter((r) => r.success);
      const failures = results.filter((r) => !r.success);

      assert.equal(successes.length, 1, 'Exactly one consumption must succeed');
      assert.equal(failures.length, 9, 'All remaining concurrent attempts must be rejected');
      for (const failure of failures) {
        assert.match(failure.reason!, /Replay attack detected/);
      }
    });

    it('persists consumed challenge state across restart, continuing to block replays', async () => {
      const challenge = challengeTracker.createChallenge({
        specId: 'spec_restart',
        specHash: 'c'.repeat(64),
        allowedMaintainerIds: ['usr_alice_lead']
      });

      const firstConsume = challengeTracker.consumeChallenge(challenge.challengeId, 'usr_alice_lead');
      assert.equal(firstConsume.success, true);

      // Simulate complete application restart with a fresh Tracker instance loading the same file
      const restartedTracker = new ChallengeTracker({ persistenceFilePath: challengeFile });
      await restartedTracker.init();

      const replayResult = restartedTracker.consumeChallenge(challenge.challengeId, 'usr_alice_lead');
      assert.equal(replayResult.success, false);
      assert.match(replayResult.reason!, /Replay attack detected/);
    });
  });

  // =========================================================================
  // 3. RUNNER APPROVAL & SPEC INTEGRITY VERIFICATION
  // =========================================================================
  describe('3. Runner Approval & Parameter Integrity Verification', () => {
    async function createAuthorizedTaskRequest(): Promise<TaskRequestMessage> {
      const investigation = await sentinel.investigate({
        rawText: 'incident: TypeError in src/auth.ts',
        senderId: 'usr_alice_lead',
        roomId: ROOM_ID
      });

      // Alice consumes the challenge
      challengeTracker.consumeChallenge(investigation.challenge.challengeId, 'usr_alice_lead');

      return sentinel.createTaskRequest({
        spec: investigation.spec,
        challengeId: investigation.challenge.challengeId,
        approvedBy: 'usr_alice_lead',
        correlationId: randomUUID()
      });
    }

    it('accepts legitimate task request matching all cryptographic and approval constraints', async () => {
      const taskRequest = await createAuthorizedTaskRequest();
      const result = await runner.handleTaskRequest(taskRequest);

      assert.equal(result.accepted, true);
      assert.equal(result.response?.status, 'QUEUED');
      assert.equal(result.response?.hopCount, 2);
    });

    it('rejects task request if diffHash was tampered with or patch diff was altered', async () => {
      const taskRequest = await createAuthorizedTaskRequest();

      // Attacker secretly replaces the patch diff while keeping old diffHash
      taskRequest.spec.patches[0]!.patchDiff = '--- a/src/auth.ts\n+++ b/src/auth.ts\n@@ -1 +1 @@\n- safe\n+ malicious_backdoor();';

      const result = await runner.handleTaskRequest(taskRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Diff hash integrity violation/);
    });

    it('rejects task request if targetRepository was altered', async () => {
      const taskRequest = await createAuthorizedTaskRequest();

      // Attacker repoints repository
      taskRequest.spec.targetRepository = 'attacker/malicious-repo';

      const result = await runner.handleTaskRequest(taskRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Spec hash integrity violation/);
    });

    it('rejects task request if baseBranch was altered', async () => {
      const taskRequest = await createAuthorizedTaskRequest();
      taskRequest.spec.baseBranch = 'production-release';

      const result = await runner.handleTaskRequest(taskRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Spec hash integrity violation/);
    });

    it('rejects task request if targetBranch was altered', async () => {
      const taskRequest = await createAuthorizedTaskRequest();
      taskRequest.spec.targetBranch = 'main'; // Attempting direct push to main!

      const result = await runner.handleTaskRequest(taskRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Spec hash integrity violation/);
    });

    it('rejects task request if verificationCommands were altered or bypassed', async () => {
      const taskRequest = await createAuthorizedTaskRequest();
      taskRequest.spec.verificationCommands = ['echo bypassed']; // Stripping real tests!

      const result = await runner.handleTaskRequest(taskRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Spec hash integrity violation/);
    });

    it('rejects task request if incidentId was altered', async () => {
      const taskRequest = await createAuthorizedTaskRequest();
      taskRequest.spec.incidentId = 'INC-DIFFERENT';

      const result = await runner.handleTaskRequest(taskRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Spec hash integrity violation/);
    });

    it('rejects task request if challenge was never authorized by an engineer (not consumed)', async () => {
      const investigation = await sentinel.investigate({
        rawText: 'incident: TypeError in src/auth.ts',
        senderId: 'usr_alice_lead',
        roomId: ROOM_ID
      });

      // Do NOT consume challenge!
      const unapprovedRequest = sentinel.createTaskRequest({
        spec: investigation.spec,
        challengeId: investigation.challenge.challengeId,
        approvedBy: 'usr_alice_lead',
        correlationId: randomUUID()
      });

      const result = await runner.handleTaskRequest(unapprovedRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /was never authorized\/consumed by a maintainer/);
    });

    it('rejects task request if approver identity does not match the maintainer who consumed the challenge', async () => {
      const taskRequest = await createAuthorizedTaskRequest();

      // Claimed approver modified to Bob, but Alice consumed it
      taskRequest.approvedBy = 'usr_bob_reviewer';

      const result = await runner.handleTaskRequest(taskRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Approver identity mismatch/);
    });

    it('rejects task request with unknown or fabricated challengeId', async () => {
      const taskRequest = await createAuthorizedTaskRequest();
      taskRequest.challengeId = 'appr_fabricated_unknown';

      const result = await runner.handleTaskRequest(taskRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /not found in challenge registry/);
    });

    it('rejects task request if approval was recorded after challenge expiration', async () => {
      const taskRequest = await createAuthorizedTaskRequest();

      // Set approvedAt to 1 hour in the future (past 5-minute expiry)
      taskRequest.approvedAt = new Date(Date.now() + 3600 * 1000).toISOString();

      const result = await runner.handleTaskRequest(taskRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Approval expired/);
    });

    it('rejects task request addressed to wrong target agent ID', async () => {
      const taskRequest = await createAuthorizedTaskRequest();
      taskRequest.targetAgentId = 'agn_other_runner';

      const result = await runner.handleTaskRequest(taskRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Targeted to 'agn_other_runner', but this Runner is/);
    });

    it('rejects task request with empty correlation ID or missing message ID', async () => {
      const taskRequest = await createAuthorizedTaskRequest();
      taskRequest.correlationId = '   ';

      const result = await runner.handleTaskRequest(taskRequest);
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Missing or invalid correlation ID/);
    });

    it('rejects agent impersonation attack: malicious agent puts trusted Sentinel ID in body payload but actual Switch sender is malicious', async () => {
      const taskRequest = await createAuthorizedTaskRequest();

      // Attacker constructs payload with senderAgentId: SENTINEL_ID, but event comes from agn_malicious_attacker
      taskRequest.senderAgentId = SENTINEL_ID;

      const result = await runner.handleTaskRequest(taskRequest, 'agn_malicious_attacker');
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Agent impersonation detected: Payload claims sender 'agn_sentinel_audit', but actual Switch event sender is 'agn_malicious_attacker'/);
    });

    it('demonstrates EventRouter pre-dispatch gate drops forged peer messages before reaching Runner', async () => {
      const taskRequest = await createAuthorizedTaskRequest();

      // Malicious agent sends message frame over Switch connection claiming to be Sentinel in the JSON body
      taskRequest.senderAgentId = SENTINEL_ID;

      const forgedEvent = createMockRoomEvent({
        senderId: 'agn_attacker_puppet', // Actual server-authenticated sender in Switch event frame
        senderName: 'Attacker Puppet',
        body: JSON.stringify(taskRequest)
      });

      const routeResult = await router.routeEvent(forgedEvent);
      assert.equal(routeResult.handled, false);
      assert.match(routeResult.reason!, /Peer task request dropped: Actual Switch sender 'agn_attacker_puppet' is not the trusted Sentinel/);
    });

    it('rejects task request if actual Switch sender is not Sentinel, even if no impersonation claimed in payload', async () => {
      const taskRequest = await createAuthorizedTaskRequest();
      taskRequest.senderAgentId = 'agn_other_unknown_agent';

      const result = await runner.handleTaskRequest(taskRequest, 'agn_other_unknown_agent');
      assert.equal(result.accepted, false);
      assert.match(result.reason!, /Unauthorized task dispatcher 'agn_other_unknown_agent'/);
    });
  });
});

