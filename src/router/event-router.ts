import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { NormalizedRoomEvent } from '../types/switch-protocol.js';
import { classifyEvent } from './event-classifier.js';
import { IdempotencyTracker } from './idempotency.js';
import { SentinelAgent } from '../sentinel/sentinel-agent.js';
import { RunnerAgent } from '../patch-runner/runner-agent.js';
import { ApprovalHandler } from '../approval/approval-handler.js';
import { SwitchAdapter } from '../room/switch-adapter.js';
import { AuditLogger } from '../audit/audit-logger.js';
import { AgentMessageSchema, TaskRequestMessage } from '../types/agent-contracts.js';
import { RemediationSpec } from '../types/remediation.js';

export interface EventRouterOptions {
  sentinel: SentinelAgent;
  runner: RunnerAgent;
  approvalHandler: ApprovalHandler;
  adapter: SwitchAdapter;
  auditLogger?: AuditLogger | undefined;
  idempotencyTracker?: IdempotencyTracker | undefined;
}

export class EventRouter extends EventEmitter {
  private sentinel: SentinelAgent;
  private runner: RunnerAgent;
  private approvalHandler: ApprovalHandler;
  private adapter: SwitchAdapter;
  private auditLogger?: AuditLogger | undefined;
  private idempotency: IdempotencyTracker;

  // Staged specifications awaiting human approval
  private activeSpecs = new Map<string, RemediationSpec>();

  constructor(options: EventRouterOptions) {
    super();
    this.sentinel = options.sentinel;
    this.runner = options.runner;
    this.approvalHandler = options.approvalHandler;
    this.adapter = options.adapter;
    this.auditLogger = options.auditLogger;
    this.idempotency = options.idempotencyTracker ?? new IdempotencyTracker();

    this.adapter.on('message', (event: NormalizedRoomEvent) => {
      this.routeEvent(event).catch((err) => this.emit('error', err));
    });
  }

  /**
   * Main routing pipeline for incoming room events.
   */
  public async routeEvent(event: NormalizedRoomEvent): Promise<{ handled: boolean; action?: string | undefined; reason?: string | undefined }> {
    // 1. Idempotency Check: Drop duplicate events
    if (!this.idempotency.markProcessed(event.eventId)) {
      return { handled: false, reason: `Duplicate event '${event.eventId}' dropped` };
    }

    // 2. Classify Event
    const classification = classifyEvent(event, this.sentinel.agentId, this.runner.agentId);

    if (classification.kind === 'IGNORED') {
      return { handled: false, reason: classification.reason };
    }

    if (this.auditLogger) {
      await this.auditLogger.log({
        actor: { type: 'SYSTEM', id: event.senderId, name: event.senderName },
        action: 'EVENT_ROUTED',
        payload: {
          eventId: event.eventId,
          roomId: event.roomId,
          kind: classification.kind
        }
      });
    }

    // 3. Route Incident Report -> Sentinel
    if (classification.kind === 'INCIDENT_REPORT') {
      const correlationId = randomUUID();
      this.idempotency.recordCorrelation(correlationId, { eventId: event.eventId, sender: event.senderId });

      const result = await this.sentinel.investigate({
        rawText: classification.text,
        senderId: event.senderId,
        roomId: event.roomId,
        correlationId
      });

      this.activeSpecs.set(result.challenge.challengeId, result.spec);

      // Post investigation findings and approval instructions back to room
      await this.adapter.sendMessage(result.formattedRoomMessage, event.threadId, event.roomId);

      this.emit('investigation_completed', result);
      return { handled: true, action: 'INCIDENT_INVESTIGATED' };
    }

    // 4. Route Approval Command -> ApprovalHandler
    if (classification.kind === 'APPROVAL_COMMAND') {
      const approvalResult = await this.approvalHandler.processApprovalCommand(
        event,
        classification.challengeId
      );

      // Post approval result back to room
      await this.adapter.sendMessage(approvalResult.formattedRoomMessage, event.threadId, event.roomId);

      if (!approvalResult.approved) {
        this.emit('approval_rejected', approvalResult);
        return { handled: true, action: 'APPROVAL_REJECTED', reason: approvalResult.reason };
      }

      // If approved, retrieve the spec and create an authorized task request for Runner
      const spec = this.activeSpecs.get(classification.challengeId);
      if (!spec) {
        return { handled: true, action: 'APPROVAL_ORPHANED_SPEC' };
      }

      const correlationId = randomUUID();
      const taskRequest = this.sentinel.createTaskRequest({
        spec,
        challengeId: classification.challengeId,
        approvedBy: event.senderId,
        correlationId
      });

      // Dispatch to Runner
      const runnerResult = await this.runner.handleTaskRequest(taskRequest);
      if (runnerResult.formattedRoomMessage) {
        await this.adapter.sendMessage(runnerResult.formattedRoomMessage, event.threadId, event.roomId);
      }

      this.emit('task_dispatched', { taskRequest, runnerResult });
      return { handled: true, action: 'TASK_APPROVED_AND_QUEUED' };
    }

    // 5. Route Structured Peer Agent Message
    if (classification.kind === 'PEER_AGENT_MESSAGE') {
      const parsed = AgentMessageSchema.safeParse(classification.payload);
      if (!parsed.success) {
        return { handled: false, reason: 'Malformed structured agent message' };
      }

      const agentMessage = parsed.data;

      // Handle Task Request targeted to Runner
      if (agentMessage.type === 'TASK_REQUEST') {
        const runnerResult = await this.runner.handleTaskRequest(agentMessage as TaskRequestMessage);
        if (runnerResult.formattedRoomMessage) {
          await this.adapter.sendMessage(runnerResult.formattedRoomMessage, event.threadId, event.roomId);
        }
        return { handled: true, action: 'RUNNER_TASK_PROCESSED' };
      }

      // Handle Task Response / Status Update targeted to Sentinel
      if (agentMessage.type === 'TASK_RESPONSE' || agentMessage.type === 'STATUS_UPDATE') {
        this.emit('agent_status_received', agentMessage);
        return { handled: true, action: 'AGENT_STATUS_TRACKED' };
      }
    }

    return { handled: false, reason: 'Unmatched action' };
  }
}
