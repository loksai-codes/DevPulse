import { z } from 'zod';
import { RemediationSpecSchema } from './remediation.js';
import { RiskReportSchema } from './risk-report.js';

export const MAX_COMMUNICATION_HOP_DEPTH = 2;

// Base header envelope present on every inter-agent communication
export const AgentMessageHeaderSchema = z.object({
  id: z.string().uuid('Message ID must be a valid UUID'),
  correlationId: z.string().min(1, 'correlationId is required to link requests and responses'),
  timestamp: z.string().datetime({ message: 'Timestamp must be an ISO-8601 string' }),
  senderAgentId: z.string().min(1, 'senderAgentId cannot be empty'),
  targetAgentId: z.string().min(1, 'targetAgentId cannot be empty'),
  hopCount: z
    .number()
    .int()
    .nonnegative()
    .max(MAX_COMMUNICATION_HOP_DEPTH, `hopCount cannot exceed ${MAX_COMMUNICATION_HOP_DEPTH}`)
});

export type AgentMessageHeader = z.infer<typeof AgentMessageHeaderSchema>;

// Task Request: Sent from Sentinel to Runner after verified human approval
export const TaskRequestMessageSchema = AgentMessageHeaderSchema.extend({
  type: z.literal('TASK_REQUEST'),
  spec: RemediationSpecSchema,
  challengeId: z.string().min(1),
  approvedBy: z.string().min(1),
  approvedAt: z.string().datetime()
});
export type TaskRequestMessage = z.infer<typeof TaskRequestMessageSchema>;

// Task Response: Acknowledgment or rejection sent from Runner back to Sentinel
export const TaskResponseMessageSchema = AgentMessageHeaderSchema.extend({
  type: z.literal('TASK_RESPONSE'),
  taskId: z.string().min(1),
  specId: z.string().min(1),
  accepted: z.boolean(),
  status: z.enum(['ACKNOWLEDGED', 'QUEUED', 'REJECTED']),
  reason: z.string().optional()
});
export type TaskResponseMessage = z.infer<typeof TaskResponseMessageSchema>;

// Task Status Update: Status progression reported by Runner
export const TaskStatusUpdateMessageSchema = AgentMessageHeaderSchema.extend({
  type: z.literal('STATUS_UPDATE'),
  taskId: z.string().min(1),
  specId: z.string().min(1),
  status: z.enum(['QUEUED', 'IN_PROGRESS', 'COMPLETED', 'FAILED']),
  message: z.string().min(1),
  details: z.record(z.unknown()).optional()
});
export type TaskStatusUpdateMessage = z.infer<typeof TaskStatusUpdateMessageSchema>;

// Risk Report Notification: Emitted by Sentinel when investigation is synthesized
export const RiskReportNotificationSchema = AgentMessageHeaderSchema.extend({
  type: z.literal('RISK_REPORT_GENERATED'),
  incidentId: z.string().min(1),
  specId: z.string().min(1),
  riskReport: RiskReportSchema,
  challengeId: z.string().min(1)
});
export type RiskReportNotification = z.infer<typeof RiskReportNotificationSchema>;

// Discriminated union of all structured agent-to-agent messages
export const AgentMessageSchema = z.discriminatedUnion('type', [
  TaskRequestMessageSchema,
  TaskResponseMessageSchema,
  TaskStatusUpdateMessageSchema,
  RiskReportNotificationSchema
]);
export type AgentMessage = z.infer<typeof AgentMessageSchema>;
