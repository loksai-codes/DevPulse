import { promises as fs, appendFileSync, readFileSync, existsSync, unlinkSync } from 'node:fs';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';

export interface ApprovalChallenge {
  challengeId: string;
  specId: string;
  specHash: string;
  createdAt: string;
  expiresAt: string;
  allowedMaintainerIds: string[];
  consumed: boolean;
  consumedBy?: string;
  consumedAt?: string;
}

export interface ChallengeTrackerOptions {
  persistenceFilePath?: string;
  defaultTtlMs?: number;
}

export class ChallengeTracker {
  private challenges = new Map<string, ApprovalChallenge>();
  private persistenceFilePath?: string;
  private defaultTtlMs: number;

  constructor(options: ChallengeTrackerOptions = {}) {
    if (options.persistenceFilePath) {
      this.persistenceFilePath = path.resolve(options.persistenceFilePath);
    }
    this.defaultTtlMs = options.defaultTtlMs ?? 5 * 60 * 1000; // 5 minutes default
  }

  /**
   * Initializes the tracker and safely reloads challenges from disk across restarts.
   */
  public async init(): Promise<void> {
    if (!this.persistenceFilePath) return;

    if (!existsSync(this.persistenceFilePath)) {
      await fs.mkdir(path.dirname(this.persistenceFilePath), { recursive: true });
      return;
    }

    try {
      const content = readFileSync(this.persistenceFilePath, 'utf8');
      const lines = content.trim().split('\n').filter(Boolean);
      for (const line of lines) {
        try {
          const parsed = JSON.parse(line) as ApprovalChallenge;
          this.challenges.set(parsed.challengeId, parsed);
        } catch {
          // ignore corrupted single lines
        }
      }
    } catch (err: unknown) {
      const error = err as NodeJS.ErrnoException;
      if (error.code !== 'ENOENT') throw error;
    }
  }

  /**
   * Creates an ephemeral approval challenge bound to a specific specification and its specHash.
   */
  public createChallenge(params: {
    specId: string;
    specHash: string;
    allowedMaintainerIds: string[];
    ttlMs?: number;
  }): ApprovalChallenge {
    const randomHex = randomBytes(4).toString('hex');
    const challengeId = `appr_${randomHex}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (params.ttlMs ?? this.defaultTtlMs));

    const challenge: ApprovalChallenge = {
      challengeId,
      specId: params.specId,
      specHash: params.specHash,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      allowedMaintainerIds: params.allowedMaintainerIds,
      consumed: false
    };

    this.challenges.set(challengeId, challenge);
    this.persistChallenge(challenge);

    return challenge;
  }

  public getChallenge(challengeId: string): ApprovalChallenge | undefined {
    return this.challenges.get(challengeId);
  }

  /**
   * Atomically consumes a challenge. Ensures:
   * 1. Challenge exists.
   * 2. Has not already been consumed (replay prevention).
   * 3. Has not expired (5-minute window).
   * 4. User is in the challenge's allowedMaintainerIds list.
   */
  public consumeChallenge(
    challengeId: string,
    userId: string,
    now: Date = new Date()
  ): { success: boolean; reason?: string; challenge?: ApprovalChallenge } {
    const challenge = this.challenges.get(challengeId);

    if (!challenge) {
      return { success: false, reason: `Challenge '${challengeId}' does not exist` };
    }

    if (challenge.consumed) {
      return {
        success: false,
        reason: `Replay attack detected: challenge '${challengeId}' was already consumed by '${challenge.consumedBy}'`
      };
    }

    const expiryTime = new Date(challenge.expiresAt).getTime();
    if (now.getTime() > expiryTime) {
      return {
        success: false,
        reason: `Challenge '${challengeId}' has expired (expired at ${challenge.expiresAt})`
      };
    }

    if (
      challenge.allowedMaintainerIds.length > 0 &&
      !challenge.allowedMaintainerIds.includes(userId)
    ) {
      return {
        success: false,
        reason: `User '${userId}' is not authorized to approve challenge '${challengeId}'`
      };
    }

    // Atomically mark consumed
    challenge.consumed = true;
    challenge.consumedBy = userId;
    challenge.consumedAt = now.toISOString();

    this.persistChallenge(challenge);

    return { success: true, challenge };
  }

  private persistChallenge(challenge: ApprovalChallenge): void {
    if (this.persistenceFilePath) {
      try {
        appendFileSync(this.persistenceFilePath, JSON.stringify(challenge) + '\n', 'utf8');
      } catch {
        // persistence fallback
      }
    }
  }

  public clear(): void {
    this.challenges.clear();
    if (this.persistenceFilePath) {
      try {
        unlinkSync(this.persistenceFilePath);
      } catch {}
    }
  }
}

