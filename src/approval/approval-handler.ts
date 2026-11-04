import { NormalizedRoomEvent } from '../types/switch-protocol.js';
import { ChallengeTracker, ApprovalChallenge } from './challenge-tracker.js';
import { AuditLogger } from '../audit/audit-logger.js';

export interface ApprovalHandlerOptions {
  maintainerAllowlist: string[];
  challengeTracker: ChallengeTracker;
  auditLogger?: AuditLogger | undefined;
}

export interface ApprovalProcessingResult {
  approved: boolean;
  reason?: string | undefined;
  challenge?: ApprovalChallenge | undefined;
  formattedRoomMessage: string;
}

export class ApprovalHandler {
  private maintainerAllowlist: string[];
  private challengeTracker: ChallengeTracker;
  private auditLogger?: AuditLogger | undefined;

  constructor(options: ApprovalHandlerOptions) {
    this.maintainerAllowlist = options.maintainerAllowlist;
    this.challengeTracker = options.challengeTracker;
    this.auditLogger = options.auditLogger;
  }

  /**
   * Processes a human approval command emitted in a Switch Room.
   */
  public async processApprovalCommand(
    event: NormalizedRoomEvent,
    challengeId: string
  ): Promise<ApprovalProcessingResult> {
    // 1. Origin Filter: Must be a native Switch Console session (bridge_id === null)
    if (!event.isNativeConsole) {
      const reason = `Approval rejected: Originates from external bridge '${event.bridgeId ?? 'unknown'}'. Approvals must be issued directly from native Switch Console.`;
      await this.logRejection(event, challengeId, reason);
      return {
        approved: false,
        reason,
        formattedRoomMessage: `⚠️ **[APPROVAL REJECTED]** ${reason}`
      };
    }

    // 2. Sender Authorization: Sender must be in MAINTAINER_ALLOWLIST
    if (!this.maintainerAllowlist.includes(event.senderId)) {
      const reason = `Approval rejected: User '${event.senderId}' (${event.senderName}) is not in the authorized maintainer allowlist.`;
      await this.logRejection(event, challengeId, reason);
      return {
        approved: false,
        reason,
        formattedRoomMessage: `⛔ **[APPROVAL FORBIDDEN]** ${reason}`
      };
    }

    // 3. Challenge Consumption: Atomic verification of existence, expiry, and non-reuse
    const consumeResult = this.challengeTracker.consumeChallenge(challengeId, event.senderId);

    if (!consumeResult.success) {
      await this.logRejection(event, challengeId, consumeResult.reason!);
      return {
        approved: false,
        reason: consumeResult.reason,
        formattedRoomMessage: `⚠️ **[APPROVAL FAILED]** ${consumeResult.reason}`
      };
    }

    const challenge = consumeResult.challenge!;

    // 4. Audit Log Success
    if (this.auditLogger) {
      await this.auditLogger.log({
        actor: { type: 'HUMAN', id: event.senderId, name: event.senderName },
        action: 'HUMAN_APPROVAL_ACCEPTED',
        specId: challenge.specId,
        payload: {
          challengeId: challenge.challengeId,
          specHash: challenge.specHash,
          approvedAt: challenge.consumedAt
        }
      });
    }

    const formattedRoomMessage = [
      `✅ **[HUMAN APPROVAL CONFIRMED]**`,
      `- **Challenge:** \`${challenge.challengeId}\``,
      `- **Specification:** \`${challenge.specId}\``,
      `- **Authorized By:** \`${event.senderName}\` (\`${event.senderId}\`)`,
      `- **Action:** Dispatching authorized remediation task to Patch & Test Runner`
    ].join('\n');

    return {
      approved: true,
      challenge,
      formattedRoomMessage
    };
  }

  private async logRejection(
    event: NormalizedRoomEvent,
    challengeId: string,
    reason: string
  ): Promise<void> {
    if (this.auditLogger) {
      await this.auditLogger.log({
        actor: { type: 'HUMAN', id: event.senderId, name: event.senderName },
        action: 'HUMAN_APPROVAL_REJECTED',
        payload: {
          challengeId,
          reason,
          isNativeConsole: event.isNativeConsole,
          bridgeId: event.bridgeId
        }
      });
    }
  }
}
