import { randomUUID } from 'node:crypto';
import {
  TaskRequestMessage,
  TaskResponseMessage,
  TaskStatusUpdateMessage,
  MAX_COMMUNICATION_HOP_DEPTH
} from '../types/agent-contracts.js';
import { AuditLogger } from '../audit/audit-logger.js';
import { ChallengeTracker } from '../approval/challenge-tracker.js';
import { computeDiffHash, computeSpecHash } from '../utils/crypto.js';

export interface RunnerAgentOptions {
  agentId: string;
  trustedSentinelId?: string | undefined;
  sentinelAgentId?: string | undefined;
  challengeTracker?: ChallengeTracker | undefined;
  auditLogger?: AuditLogger | undefined;
}

export interface RunnerTaskResult {
  accepted: boolean;
  reason?: string | undefined;
  response?: TaskResponseMessage | undefined;
  statusUpdate?: TaskStatusUpdateMessage | undefined;
  formattedRoomMessage?: string | undefined;
}

export class RunnerAgent {
  public readonly agentId: string;
  public readonly trustedSentinelId: string;
  private challengeTracker?: ChallengeTracker | undefined;
  private auditLogger?: AuditLogger | undefined;

  constructor(options: RunnerAgentOptions) {
    this.agentId = options.agentId;
    this.trustedSentinelId = (options.trustedSentinelId ?? options.sentinelAgentId) || '';
    this.challengeTracker = options.challengeTracker;
    this.auditLogger = options.auditLogger;
  }

  /**
   * Receives and validates an authorized task request strictly from Sentinel.
   * STRICT BOUNDARY: Does not execute shell commands, git operations, or PR creation.
   */
  public async handleTaskRequest(
    request: TaskRequestMessage,
    actualSwitchSenderId?: string | undefined
  ): Promise<RunnerTaskResult> {
    const taskId = `task_${request.spec.id}_${Date.now().toString().slice(-4)}`;

    // 1. Message and Correlation ID Validation
    if (!request.id || typeof request.id !== 'string') {
      return {
        accepted: false,
        reason: 'Task request rejected: Missing or invalid message ID.',
        formattedRoomMessage: '⛔ **[RUNNER TASK_REQUEST REJECTED]** Missing or invalid message ID.'
      };
    }

    if (!request.correlationId || typeof request.correlationId !== 'string' || !request.correlationId.trim()) {
      return {
        accepted: false,
        reason: 'Task request rejected: Missing or invalid correlation ID.',
        formattedRoomMessage: '⛔ **[RUNNER TASK_REQUEST REJECTED]** Missing or invalid correlation ID.'
      };
    }

    // 2. Addressing Verification: Must be targeted specifically to this Runner
    if (request.targetAgentId !== this.agentId) {
      return {
        accepted: false,
        reason: `Task request rejected: Targeted to '${request.targetAgentId}', but this Runner is '${this.agentId}'.`,
        formattedRoomMessage: `⛔ **[RUNNER TASK_REQUEST REJECTED]** Task targeted to '${request.targetAgentId}', not this Runner.`
      };
    }

    // 3. Sender Authentication: Check actual server-authenticated Switch sender metadata
    const effectiveSender = actualSwitchSenderId ?? request.senderAgentId;

    // Detect agent impersonation: payload claiming Sentinel while actual Switch sender is different
    if (actualSwitchSenderId && request.senderAgentId !== actualSwitchSenderId) {
      if (this.auditLogger) {
        await this.auditLogger.log({
          actor: { type: 'PATCH_RUNNER', id: this.agentId, name: 'Patch Runner' },
          action: 'TASK_REJECTED_AGENT_IMPERSONATION',
          specId: request.spec.id,
          payload: {
            claimedPayloadSender: request.senderAgentId,
            actualSwitchSender: actualSwitchSenderId,
            trustedSentinel: this.trustedSentinelId,
            correlationId: request.correlationId
          }
        });
      }
      return {
        accepted: false,
        reason: `Agent impersonation detected: Payload claims sender '${request.senderAgentId}', but actual Switch event sender is '${actualSwitchSenderId}'.`,
        formattedRoomMessage: `⛔ **[RUNNER TASK_REQUEST REJECTED]** Agent impersonation detected (claimed '${request.senderAgentId}', actual '${actualSwitchSenderId}').`
      };
    }

    if (effectiveSender !== this.trustedSentinelId) {
      if (this.auditLogger) {
        await this.auditLogger.log({
          actor: { type: 'PATCH_RUNNER', id: this.agentId, name: 'Patch Runner' },
          action: 'TASK_REJECTED_UNAUTHORIZED_SENDER',
          specId: request.spec.id,
          payload: {
            claimedSender: request.senderAgentId,
            actualSwitchSender: actualSwitchSenderId,
            trustedSentinel: this.trustedSentinelId,
            correlationId: request.correlationId
          }
        });
      }
      return {
        accepted: false,
        reason: `Unauthorized task dispatcher '${effectiveSender}'. Tasks are only accepted from trusted Sentinel '${this.trustedSentinelId}'.`,
        formattedRoomMessage: `⛔ **[RUNNER TASK_REQUEST REJECTED]** Sender '${effectiveSender}' is not the authorized Sentinel.`
      };
    }

    // 4. Hop-Depth Protection: Prevent infinite loops
    if (request.hopCount > MAX_COMMUNICATION_HOP_DEPTH) {
      return {
        accepted: false,
        reason: `Communication hop count ${request.hopCount} exceeds maximum allowed depth (${MAX_COMMUNICATION_HOP_DEPTH})`,
        formattedRoomMessage: `⛔ **[RUNNER TASK_REQUEST REJECTED]** Hop count ${request.hopCount} exceeds maximum allowed depth.`
      };
    }

    // 5. Human Approval Gate Verification: Task must carry verified maintainer approval
    if (!request.approvedBy || !request.challengeId || !request.approvedAt) {
      if (this.auditLogger) {
        await this.auditLogger.log({
          actor: { type: 'PATCH_RUNNER', id: this.agentId, name: 'Patch Runner' },
          action: 'TASK_REJECTED_MISSING_APPROVAL',
          specId: request.spec.id,
          payload: { correlationId: request.correlationId }
        });
      }
      return {
        accepted: false,
        reason: 'Task request lacks valid human maintainer approval confirmation (approvedBy, challengeId, and approvedAt required)',
        formattedRoomMessage: '⛔ **[RUNNER TASK_REQUEST REJECTED]** Missing complete human approval confirmation.'
      };
    }

    // 6. Diff Hash Re-computation & Verification: Verify patch contents
    const computedDiffHash = computeDiffHash(request.spec.patches);
    if (computedDiffHash !== request.spec.diffHash) {
      if (this.auditLogger) {
        await this.auditLogger.log({
          actor: { type: 'PATCH_RUNNER', id: this.agentId, name: 'Patch Runner' },
          action: 'TASK_REJECTED_DIFF_HASH_MISMATCH',
          specId: request.spec.id,
          payload: {
            computedDiffHash,
            claimedDiffHash: request.spec.diffHash
          }
        });
      }
      return {
        accepted: false,
        reason: `Diff hash integrity violation: computed '${computedDiffHash}' does not match spec diffHash '${request.spec.diffHash}'. Patches may have been altered.`,
        formattedRoomMessage: '⛔ **[RUNNER TASK_REQUEST REJECTED]** Diff hash integrity violation.'
      };
    }

    // 7. Spec Hash Re-computation & Verification: Verify incidentId, repo, branches, diffHash, commands
    const computedSpecHash = computeSpecHash(request.spec);
    if (computedSpecHash !== request.spec.specHash) {
      if (this.auditLogger) {
        await this.auditLogger.log({
          actor: { type: 'PATCH_RUNNER', id: this.agentId, name: 'Patch Runner' },
          action: 'TASK_REJECTED_SPEC_HASH_MISMATCH',
          specId: request.spec.id,
          payload: {
            computedSpecHash,
            claimedSpecHash: request.spec.specHash
          }
        });
      }
      return {
        accepted: false,
        reason: `Spec hash integrity violation: computed '${computedSpecHash}' does not match specHash '${request.spec.specHash}'. Execution parameters were altered.`,
        formattedRoomMessage: '⛔ **[RUNNER TASK_REQUEST REJECTED]** Spec hash integrity violation.'
      };
    }

    // 8. Challenge Registry Verification (if challengeTracker provided)
    if (this.challengeTracker) {
      const challenge = this.challengeTracker.getChallenge(request.challengeId);
      if (!challenge) {
        return {
          accepted: false,
          reason: `Approval challenge '${request.challengeId}' not found in challenge registry.`,
          formattedRoomMessage: `⛔ **[RUNNER TASK_REQUEST REJECTED]** Challenge '${request.challengeId}' not found.`
        };
      }

      if (!challenge.consumed) {
        return {
          accepted: false,
          reason: `Approval challenge '${request.challengeId}' was never authorized/consumed by a maintainer.`,
          formattedRoomMessage: `⛔ **[RUNNER TASK_REQUEST REJECTED]** Challenge '${request.challengeId}' was not authorized.`
        };
      }

      if (challenge.consumedBy !== request.approvedBy) {
        return {
          accepted: false,
          reason: `Approver identity mismatch: challenge authorized by '${challenge.consumedBy}', not '${request.approvedBy}'.`,
          formattedRoomMessage: `⛔ **[RUNNER TASK_REQUEST REJECTED]** Approver identity mismatch.`
        };
      }

      if (challenge.specHash !== request.spec.specHash) {
        return {
          accepted: false,
          reason: `Approved specHash mismatch: challenge was authorized for '${challenge.specHash}', but task carries '${request.spec.specHash}'.`,
          formattedRoomMessage: `⛔ **[RUNNER TASK_REQUEST REJECTED]** Approved specHash mismatch.`
        };
      }

      if (challenge.specId !== request.spec.id) {
        return {
          accepted: false,
          reason: `Approved specId mismatch: challenge authorized for '${challenge.specId}', but task carries '${request.spec.id}'.`,
          formattedRoomMessage: `⛔ **[RUNNER TASK_REQUEST REJECTED]** Approved specId mismatch.`
        };
      }

      const approvedTime = new Date(request.approvedAt).getTime();
      const expiryTime = new Date(challenge.expiresAt).getTime();
      if (approvedTime > expiryTime) {
        return {
          accepted: false,
          reason: `Approval expired: approval recorded at ${request.approvedAt}, past challenge expiry ${challenge.expiresAt}.`,
          formattedRoomMessage: `⛔ **[RUNNER TASK_REQUEST REJECTED]** Approval has expired.`
        };
      }
    }

    // 4. Formulate Acknowledged Task Response (increments hopCount)
    const response: TaskResponseMessage = {
      id: randomUUID(),
      type: 'TASK_RESPONSE',
      correlationId: request.correlationId,
      timestamp: new Date().toISOString(),
      senderAgentId: this.agentId,
      targetAgentId: this.trustedSentinelId,
      hopCount: request.hopCount + 1,
      taskId,
      specId: request.spec.id,
      accepted: true,
      status: 'QUEUED'
    };

    const statusUpdate: TaskStatusUpdateMessage = {
      id: randomUUID(),
      type: 'STATUS_UPDATE',
      correlationId: request.correlationId,
      timestamp: new Date().toISOString(),
      senderAgentId: this.agentId,
      targetAgentId: this.trustedSentinelId,
      hopCount: request.hopCount + 1,
      taskId,
      specId: request.spec.id,
      status: 'QUEUED',
      message: `Task ${taskId} accepted for ${request.spec.targetBranch}`
    };

    const formattedRoomMessage = [
      `🚀 **[PATCH & TEST RUNNER] Task Queued: \`${taskId}\`**`,
      `- **Target Repository:** \`${request.spec.targetRepository}\``,
      `- **Target Branch:** \`${request.spec.targetBranch}\``,
      `- **Approved By:** \`${request.approvedBy}\``,
      `- **Status:** Queued (Execution staged for Phase 3)`
    ].join('\n');

    if (this.auditLogger) {
      await this.auditLogger.log({
        actor: { type: 'PATCH_RUNNER', id: this.agentId, name: 'Patch Runner' },
        action: 'TASK_ACCEPTED_AND_QUEUED',
        specId: request.spec.id,
        payload: {
          taskId,
          correlationId: request.correlationId,
          approvedBy: request.approvedBy,
          targetBranch: request.spec.targetBranch
        }
      });
    }

    return {
      accepted: true,
      response,
      statusUpdate,
      formattedRoomMessage
    };
  }
}
