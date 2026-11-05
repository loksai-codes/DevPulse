import { NormalizedRoomEvent } from '../types/switch-protocol.js';
import { ChallengeTracker, ApprovalChallenge } from './challenge-tracker.js';
import { AuditLogger } from '../audit/audit-logger.js';

export interface ApprovalHandlerOptions {
  maintainerAllowlist: string[];
  challengeTracker: ChallengeTracker;
  auditLogger?: AuditLogger | undefined;
}

export interface ApprovalProcessingContext {
  incidentId?: string | undefined;
  specId?: string | undefined;
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

  public getAuditLogger(): AuditLogger | undefined {
    return this.auditLogger;
  }

  public setAuditLogger(logger: AuditLogger): void {
    this.auditLogger = logger;
  }

  /**
   * Processes a human approval command emitted in a Switch Room.
   */
  public async processApprovalCommand(
    event: NormalizedRoomEvent,
    challengeId: string,
    context?: ApprovalProcessingContext
  ): Promise<ApprovalProcessingResult> {
    // 1. Origin Filter: Must be a native Switch Console session (bridge_id === null)
    if (!event.isNativeConsole || event.bridgeId !== null) {
      const reason = `Approval rejected: Originates from external bridge '${event.bridgeId ?? 'unknown'}'. Approvals must be issued directly from native Switch Console.`;
      await this.logRejection(event, challengeId, reason, context);
      return {
        approved: false,
        reason,
        formattedRoomMessage: `⚠️ **[APPROVAL REJECTED]** ${reason}`
      };
    }

    // 2. Reject self-messages and automated bots/agents attempting to approve
    if (event.isSelfMessage) {
      const reason = 'Approval rejected: Autonomous agent self-messages cannot issue approvals.';
      await this.logRejection(event, challengeId, reason, context);
      return {
        approved: false,
        reason,
        formattedRoomMessage: `⛔ **[APPROVAL FORBIDDEN]** ${reason}`
      };
    }

    if (!event.senderType || event.senderType !== 'USER') {
      const reason = `Approval rejected: Sender type '${event.senderType ?? 'MISSING'}' is untrusted or missing. Switch approvals strictly require verified 'USER' senderType.`;
      await this.logRejection(event, challengeId, reason, context);
      return {
        approved: false,
        reason,
        formattedRoomMessage: `⛔ **[APPROVAL FORBIDDEN]** ${reason}`
      };
    }

    // 3. Sender Authorization: Server-provided senderId must be in MAINTAINER_ALLOWLIST
    if (!event.senderId || !this.maintainerAllowlist.includes(event.senderId)) {
      const reason = `Approval rejected: User '${event.senderId || 'unknown'}' (${event.senderName || 'unknown'}) is not in the authorized maintainer allowlist.`;
      await this.logRejection(event, challengeId, reason, context);
      return {
        approved: false,
        reason,
        formattedRoomMessage: `⛔ **[APPROVAL FORBIDDEN]** ${reason}`
      };
    }

    // 4. Challenge Consumption: Atomic verification of existence, expiry, and non-reuse
    const consumeResult = this.challengeTracker.consumeChallenge(challengeId, event.senderId);

    if (!consumeResult.success) {
      await this.logRejection(event, challengeId, consumeResult.reason!, context);
      return {
        approved: false,
        reason: consumeResult.reason,
        formattedRoomMessage: `⚠️ **[APPROVAL FAILED]** ${consumeResult.reason}`
      };
    }

    const challenge = consumeResult.challenge!;

    // 4. Audit Log Success
    if (this.auditLogger) {
      const actorType = event.senderType === 'USER' ? 'HUMAN' : 'SYSTEM';
      await this.auditLogger.log({
        actor: { type: actorType, id: event.senderId || 'unknown', name: event.senderName || 'unknown' },
        action: 'HUMAN_APPROVAL_ACCEPTED',
        specId: challenge.specId,
        ...(context?.incidentId ? { incidentId: context.incidentId } : {}),
        payload: {
          challengeId: challenge.challengeId,
          specHash: challenge.specHash,
          outcome: 'approved',
          actorId: event.senderId || 'unknown',
          requesterId: event.senderId || 'unknown',
          approvedAt: challenge.consumedAt,
          timestamp: new Date().toISOString()
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
    reason: string,
    context?: ApprovalProcessingContext
  ): Promise<void> {
    if (this.auditLogger) {
      const actorType = event.senderType === 'USER' ? 'HUMAN' : 'SYSTEM';
      await this.auditLogger.log({
        actor: { type: actorType, id: event.senderId || 'unknown', name: event.senderName || 'unknown' },
        action: 'HUMAN_APPROVAL_REJECTED',
        ...(context?.specId ? { specId: context.specId } : {}),
        ...(context?.incidentId ? { incidentId: context.incidentId } : {}),
        payload: {
          challengeId,
          outcome: 'rejected',
          reason,
          actorId: event.senderId || 'unknown',
          requesterId: event.senderId || 'unknown',
          timestamp: new Date().toISOString(),
          isNativeConsole: event.isNativeConsole,
          bridgeId: event.bridgeId
        }
      });
    }
  }
}
