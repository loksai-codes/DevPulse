import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { ChallengeTracker } from '../src/approval/challenge-tracker.js';

describe('Approval Challenge Tracker (Ephemeral & Persistent Replay Protection)', () => {
  let storageFile: string;

  beforeEach(() => {
    storageFile = join(tmpdir(), `test-challenges-${randomUUID()}.jsonl`);
  });

  afterEach(() => {
    if (existsSync(storageFile)) {
      try {
        unlinkSync(storageFile);
      } catch {
        // cleanup ignore
      }
    }
  });

  it('generates an ephemeral challenge bound to the exact specHash with a 5-minute TTL', () => {
    const tracker = new ChallengeTracker({ persistenceFilePath: storageFile });
    const specHash = 'e'.repeat(64);

    const challenge = tracker.createChallenge({
      specId: 'spec_123',
      specHash,
      allowedMaintainerIds: ['usr_alice', 'usr_bob']
    });

    assert.ok(challenge.challengeId.startsWith('appr_'));
    assert.equal(challenge.specId, 'spec_123');
    assert.equal(challenge.specHash, specHash);
    assert.equal(challenge.consumed, false);
    assert.deepEqual(challenge.allowedMaintainerIds, ['usr_alice', 'usr_bob']);

    const createdTime = new Date(challenge.createdAt).getTime();
    const expiresTime = new Date(challenge.expiresAt).getTime();
    const diffSeconds = Math.round((expiresTime - createdTime) / 1000);
    assert.equal(diffSeconds, 300); // 5 minutes exactly
  });

  it('allows authorized maintainer to consume challenge once', () => {
    const tracker = new ChallengeTracker({ persistenceFilePath: storageFile });
    const specHash = 'e'.repeat(64);

    const challenge = tracker.createChallenge({
      specId: 'spec_123',
      specHash,
      allowedMaintainerIds: ['usr_alice']
    });

    const result = tracker.consumeChallenge(challenge.challengeId, 'usr_alice');

    assert.equal(result.success, true);
    assert.equal(result.challenge?.consumed, true);
    assert.equal(result.challenge?.consumedBy, 'usr_alice');
  });

  it('atomically blocks replay attacks (cannot consume the same challenge twice)', () => {
    const tracker = new ChallengeTracker({ persistenceFilePath: storageFile });
    const specHash = 'e'.repeat(64);

    const challenge = tracker.createChallenge({
      specId: 'spec_123',
      specHash,
      allowedMaintainerIds: ['usr_alice']
    });

    // 1st consumption succeeds
    const firstResult = tracker.consumeChallenge(challenge.challengeId, 'usr_alice');
    assert.equal(firstResult.success, true);

    // 2nd consumption must fail
    const secondResult = tracker.consumeChallenge(challenge.challengeId, 'usr_alice');
    assert.equal(secondResult.success, false);
    assert.match(secondResult.reason!, /Replay attack detected/);
  });

  it('rejects an approval if the maintainer is not in the allowlist', () => {
    const tracker = new ChallengeTracker({ persistenceFilePath: storageFile });
    const specHash = 'e'.repeat(64);

    const challenge = tracker.createChallenge({
      specId: 'spec_123',
      specHash,
      allowedMaintainerIds: ['usr_alice']
    });

    const result = tracker.consumeChallenge(challenge.challengeId, 'usr_mallory_unauthorized');

    assert.equal(result.success, false);
    assert.match(result.reason!, /not authorized to approve challenge/);
  });

  it('rejects consumption of an expired challenge', () => {
    const tracker = new ChallengeTracker({ persistenceFilePath: storageFile });
    const specHash = 'e'.repeat(64);

    // Create challenge with TTL of -10 seconds (already expired)
    const challenge = tracker.createChallenge({
      specId: 'spec_123',
      specHash,
      allowedMaintainerIds: ['usr_alice'],
      ttlMs: -10000
    });

    const result = tracker.consumeChallenge(challenge.challengeId, 'usr_alice');

    assert.equal(result.success, false);
    assert.match(result.reason!, /has expired/);
  });

  it('persists challenges and consumed states across application restarts', async () => {
    const specHash = 'e'.repeat(64);

    // Process 1: Create and consume one challenge, create another pending
    const tracker1 = new ChallengeTracker({ persistenceFilePath: storageFile });
    await tracker1.init();

    const challenge1 = tracker1.createChallenge({
      specId: 'spec_1',
      specHash,
      allowedMaintainerIds: ['usr_alice']
    });
    const challenge2 = tracker1.createChallenge({
      specId: 'spec_2',
      specHash,
      allowedMaintainerIds: ['usr_bob']
    });

    const consumeResult1 = tracker1.consumeChallenge(challenge1.challengeId, 'usr_alice');
    assert.equal(consumeResult1.success, true);

    // Process 2: Restart tracker pointing to the same storage file
    const tracker2 = new ChallengeTracker({ persistenceFilePath: storageFile });
    await tracker2.init();

    // challenge1 must still be CONSUMED and reject replay
    const replayResult = tracker2.consumeChallenge(challenge1.challengeId, 'usr_alice');
    assert.equal(replayResult.success, false);
    assert.match(replayResult.reason!, /Replay attack detected/);

    // challenge2 must still be PENDING and successfully consumable by usr_bob
    const consumeResult2 = tracker2.consumeChallenge(challenge2.challengeId, 'usr_bob');
    assert.equal(consumeResult2.success, true);
    assert.equal(consumeResult2.challenge?.consumedBy, 'usr_bob');
  });
});
