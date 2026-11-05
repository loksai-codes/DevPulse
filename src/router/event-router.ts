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
  canonicalRepository?: string | undefined;
}

export class EventRouter extends EventEmitter {
  private sentinel: SentinelAgent;
  private runner: RunnerAgent;
  private approvalHandler: ApprovalHandler;
  private adapter: SwitchAdapter;
  private auditLogger?: AuditLogger | undefined;
  private idempotency: IdempotencyTracker;
  private canonicalRepository?: string | undefined;

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
    this.canonicalRepository = options.canonicalRepository;

    // Ensure ApprovalHandler has auditLogger if router has one and handler does not
    if (this.auditLogger && typeof (this.approvalHandler as any).setAuditLogger === 'function') {
      if (!(this.approvalHandler as any).getAuditLogger?.()) {
        (this.approvalHandler as any).setAuditLogger(this.auditLogger);
      }
    }

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
        canonicalRepository: this.canonicalRepository,
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
      const stagedSpec = this.activeSpecs.get(classification.challengeId);
      const approvalResult = await this.approvalHandler.processApprovalCommand(
        event,
        classification.challengeId,
        stagedSpec ? { incidentId: stagedSpec.incidentId, specId: stagedSpec.id } : undefined
      );

      // Post approval result back to room
      await this.adapter.sendMessage(approvalResult.formattedRoomMessage, event.threadId, event.roomId);

      if (!approvalResult.approved) {
        this.emit('approval_rejected', approvalResult);
        return { handled: true, action: 'APPROVAL_REJECTED', reason: approvalResult.reason };
      }

      // If approved, retrieve the spec and create an authorized task request for Runner
      const spec = stagedSpec ?? this.activeSpecs.get(classification.challengeId);
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

      // Dispatch to Runner with verified Sentinel in-process identity
      const runnerResult = await this.runner.handleTaskRequest(taskRequest, this.sentinel.agentId);
      if (runnerResult.formattedRoomMessage) {
        await this.adapter.sendMessage(runnerResult.formattedRoomMessage, event.threadId, event.roomId);
      }

      const action = runnerResult.executionEvidence ? 'TASK_APPROVED_AND_EXECUTED' : 'TASK_APPROVED_AND_QUEUED';
      this.emit('task_dispatched', { taskRequest, runnerResult });
      if (runnerResult.executionEvidence) {
        this.emit('task_executed', { taskRequest, runnerResult });
      }
      return { handled: true, action };
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
        // Pre-dispatch security gate: Validate actual Switch event sender against trusted Sentinel
        if (event.senderId !== this.sentinel.agentId) {
          if (this.auditLogger) {
            await this.auditLogger.log({
              actor: { type: 'SYSTEM', id: event.senderId, name: event.senderName },
              action: 'TASK_REQUEST_DROPPED_UNTRUSTED_SWITCH_SENDER',
              payload: {
                actualSenderId: event.senderId,
                trustedSentinelId: this.sentinel.agentId,
                claimedSenderAgentId: (agentMessage as TaskRequestMessage).senderAgentId
              }
            });
          }
          return {
            handled: false,
            reason: `Peer task request dropped: Actual Switch sender '${event.senderId}' is not the trusted Sentinel '${this.sentinel.agentId}'`
          };
        }

        const runnerResult = await this.runner.handleTaskRequest(
          agentMessage as TaskRequestMessage,
          event.senderId
        );
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
