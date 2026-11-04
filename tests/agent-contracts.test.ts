import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  AgentMessageSchema,
  TaskRequestMessageSchema,
  TaskResponseMessageSchema,
  TaskStatusUpdateMessageSchema,
  RiskReportNotificationSchema
} from '../src/types/agent-contracts.js';
import { RemediationSpec } from '../src/types/remediation.js';

describe('Agent-to-Agent Message Contracts & Hop-Depth Protection', () => {
  const sampleSpec: RemediationSpec = {
    id: 'spec_inc123',
    incidentId: 'INC-001234',
    createdAt: new Date().toISOString(),
    targetRepository: 'owner/devpulse-demo',
    baseBranch: 'main',
    targetBranch: 'devpulse/fix-inc123',
    errorSignature: 'TypeError: Cannot read properties of undefined',
    rootCause: 'Missing null check in auth session handler',
    patches: [
      {
        path: 'src/auth.ts',
        action: 'MODIFY',
        patchDiff: '--- a/src/auth.ts\n+++ b/src/auth.ts\n@@ -1,2 +1,2 @@\n- foo\n+ bar'
      }
    ],
    diffHash: 'a'.repeat(64),
    riskReport: {
      riskScore: 15,
      riskLevel: 'LOW',
      blastRadius: ['src/auth.ts'],
      testsImpacted: ['tests/auth.test.ts'],
      rollbackStrategy: 'Revert commit',
      safetyGuarantees: ['Backward compatible']
    },
    verificationCommands: ['npm test'],
    status: 'PROPOSED',
    specHash: 'b'.repeat(64)
  };

  it('validates a compliant TaskRequest from Sentinel to Runner (hop 1)', () => {
    const correlationId = randomUUID();
    const taskRequest = {
      id: randomUUID(),
      type: 'TASK_REQUEST',
      correlationId,
      timestamp: new Date().toISOString(),
      senderAgentId: 'agn_sentinel_01',
      targetAgentId: 'agn_runner_01',
      hopCount: 1,
      spec: sampleSpec,
      challengeId: 'appr_deadbeef1234',
      approvedBy: 'usr_lead_maintainer',
      approvedAt: new Date().toISOString()
    };

    const parsed = TaskRequestMessageSchema.safeParse(taskRequest);
    assert.equal(parsed.success, true);
    if (parsed.success) {
      assert.equal(parsed.data.hopCount, 1);
      assert.equal(parsed.data.correlationId, correlationId);
    }
  });

  it('validates a compliant TaskResponse from Runner to Sentinel (hop 2)', () => {
    const correlationId = randomUUID();
    const taskResponse = {
      id: randomUUID(),
      type: 'TASK_RESPONSE',
      correlationId,
      timestamp: new Date().toISOString(),
      senderAgentId: 'agn_runner_01',
      targetAgentId: 'agn_sentinel_01',
      hopCount: 2,
      taskId: 'task_abc_123',
      specId: sampleSpec.id,
      accepted: true,
      status: 'QUEUED',
      reason: 'Remediation task queued in Runner (sandboxed verification staged)'
    };

    const parsed = TaskResponseMessageSchema.safeParse(taskResponse);
    assert.equal(parsed.success, true);
    if (parsed.success) {
      assert.equal(parsed.data.hopCount, 2);
    }
  });

  it('validates a status update message', () => {
    const correlationId = randomUUID();
    const statusUpdate = {
      id: randomUUID(),
      type: 'STATUS_UPDATE',
      correlationId,
      timestamp: new Date().toISOString(),
      senderAgentId: 'agn_runner_01',
      targetAgentId: 'agn_sentinel_01',
      hopCount: 2,
      taskId: 'task_abc_123',
      specId: sampleSpec.id,
      status: 'IN_PROGRESS',
      message: 'Running verification commands in sandboxed environment'
    };

    const parsed = TaskStatusUpdateMessageSchema.safeParse(statusUpdate);
    assert.equal(parsed.success, true);
  });

  it('validates a RiskReport notification', () => {
    const correlationId = randomUUID();
    const notification = {
      id: randomUUID(),
      type: 'RISK_REPORT_GENERATED',
      correlationId,
      timestamp: new Date().toISOString(),
      senderAgentId: 'agn_sentinel_01',
      targetAgentId: 'agn_runner_01',
      hopCount: 1,
      incidentId: sampleSpec.incidentId,
      specId: sampleSpec.id,
      riskReport: sampleSpec.riskReport,
      challengeId: 'appr_deadbeef1234'
    };

    const parsed = RiskReportNotificationSchema.safeParse(notification);
    assert.equal(parsed.success, true);
  });

  it('enforces maximum communication depth of 2 (rejects hopCount > 2)', () => {
    const invalidHopRequest = {
      id: randomUUID(),
      type: 'TASK_REQUEST',
      correlationId: randomUUID(),
      timestamp: new Date().toISOString(),
      senderAgentId: 'agn_sentinel_01',
      targetAgentId: 'agn_runner_01',
      hopCount: 3, // Exceeds limit of 2!
      spec: sampleSpec,
      challengeId: 'appr_deadbeef1234',
      approvedBy: 'usr_lead_maintainer',
      approvedAt: new Date().toISOString()
    };

    const parsed = AgentMessageSchema.safeParse(invalidHopRequest);
    assert.equal(parsed.success, false);
    if (!parsed.success) {
      assert.match(parsed.error.issues[0]!.message, /hopCount cannot exceed 2/);
    }
  });

  it('rejects negative hopCount', () => {
    const negativeHopRequest = {
      id: randomUUID(),
      type: 'TASK_REQUEST',
      correlationId: randomUUID(),
      timestamp: new Date().toISOString(),
      senderAgentId: 'agn_sentinel_01',
      targetAgentId: 'agn_runner_01',
      hopCount: -1,
      spec: sampleSpec,
      challengeId: 'appr_deadbeef1234',
      approvedBy: 'usr_lead_maintainer',
      approvedAt: new Date().toISOString()
    };

    const parsed = AgentMessageSchema.safeParse(negativeHopRequest);
    assert.equal(parsed.success, false);
  });

  it('rejects agent messages with missing or empty correlation IDs', () => {
    const missingCorrelation = {
      id: randomUUID(),
      type: 'TASK_REQUEST',
      correlationId: '',
      timestamp: new Date().toISOString(),
      senderAgentId: 'agn_sentinel_01',
      targetAgentId: 'agn_runner_01',
      hopCount: 1,
      spec: sampleSpec,
      challengeId: 'appr_deadbeef1234',
      approvedBy: 'usr_lead_maintainer',
      approvedAt: new Date().toISOString()
    };

    const parsed = AgentMessageSchema.safeParse(missingCorrelation);
    assert.equal(parsed.success, false);
  });
});
