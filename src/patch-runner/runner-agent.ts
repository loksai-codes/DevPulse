import { randomUUID } from 'node:crypto';
import {
  TaskRequestMessage,
  TaskResponseMessage,
  TaskStatusUpdateMessage,
  MAX_COMMUNICATION_HOP_DEPTH
} from '../types/agent-contracts.js';
import { AuditLogger } from '../audit/audit-logger.js';

export interface RunnerAgentOptions {
  agentId: string;
  trustedSentinelId: string;
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
  private auditLogger?: AuditLogger | undefined;

  constructor(options: RunnerAgentOptions) {
    this.agentId = options.agentId;
    this.trustedSentinelId = options.trustedSentinelId;
    this.auditLogger = options.auditLogger;
  }

  /**
   * Receives and validates an authorized task request strictly from Sentinel.
   * STRICT BOUNDARY: Does not execute shell commands, git operations, or PR creation.
   */
  public async handleTaskRequest(request: TaskRequestMessage): Promise<RunnerTaskResult> {
    const taskId = `task_${request.spec.id}_${Date.now().toString().slice(-4)}`;

    // 1. Sender Authentication: Must come strictly from the trusted Sentinel identity
    if (request.senderAgentId !== this.trustedSentinelId) {
      if (this.auditLogger) {
        await this.auditLogger.log({
          actor: { type: 'PATCH_RUNNER', id: this.agentId, name: 'Patch Runner' },
          action: 'TASK_REJECTED_UNAUTHORIZED_SENDER',
          specId: request.spec.id,
          payload: {
            claimedSender: request.senderAgentId,
            trustedSentinel: this.trustedSentinelId,
            correlationId: request.correlationId
          }
        });
      }
      return {
        accepted: false,
        reason: `Unauthorized task dispatcher '${request.senderAgentId}'. Tasks are only accepted from trusted Sentinel '${this.trustedSentinelId}'.`
      };
    }

    // 2. Hop-Depth Protection: Prevent infinite loops
    if (request.hopCount > MAX_COMMUNICATION_HOP_DEPTH) {
      return {
        accepted: false,
        reason: `Communication hop count ${request.hopCount} exceeds maximum allowed depth (${MAX_COMMUNICATION_HOP_DEPTH})`
      };
    }

    // 3. Human Approval Gate Verification: Task must carry verified maintainer approval
    if (!request.approvedBy || !request.challengeId) {
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
        reason: 'Task request lacks valid human maintainer approval confirmation'
      };
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
