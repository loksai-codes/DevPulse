import { randomUUID } from 'node:crypto';
import { RemediationSpec } from '../types/remediation.js';
import { RiskReport, calculateRiskLevel } from '../types/risk-report.js';
import { computeDiffHash, computeSpecHash } from '../utils/crypto.js';
import { ChallengeTracker, ApprovalChallenge } from '../approval/challenge-tracker.js';
import { AuditLogger } from '../audit/audit-logger.js';
import { TaskRequestMessage } from '../types/agent-contracts.js';
import { InvestigationReport } from './types.js';
import { parseStackTrace } from './analyzer/stack-trace-parser.js';
import { classifyIncident } from './analyzer/incident-classifier.js';
import { diagnoseIncident } from './analyzer/root-cause-engine.js';
import { assessImpact } from './analyzer/impact-assessor.js';
import { evaluateRisk } from './analyzer/risk-evaluator.js';
import { buildInvestigationReport } from './analyzer/investigation-reporter.js';

export interface SentinelAgentOptions {
  agentId: string;
  runnerAgentId: string;
  maintainerAllowlist: string[];
  challengeTracker: ChallengeTracker;
  auditLogger?: AuditLogger | undefined;
}

export interface InvestigationResult {
  incidentId: string;
  spec: RemediationSpec;
  riskReport: RiskReport;
  challenge: ApprovalChallenge;
  formattedRoomMessage: string;
}

export class SentinelAgent {
  public readonly agentId: string;
  public readonly runnerAgentId: string;
  private maintainerAllowlist: string[];
  private challengeTracker: ChallengeTracker;
  private auditLogger?: AuditLogger | undefined;

  constructor(options: SentinelAgentOptions) {
    this.agentId = options.agentId;
    this.runnerAgentId = options.runnerAgentId;
    this.maintainerAllowlist = options.maintainerAllowlist;
    this.challengeTracker = options.challengeTracker;
    this.auditLogger = options.auditLogger;
  }

  /**
   * Investigates an incident description or stack trace and synthesizes a remediation proposal.
   */
  public async investigate(params: {
    rawText: string;
    senderId: string;
    roomId: string;
    correlationId?: string;
  }): Promise<InvestigationResult> {
    const correlationId = params.correlationId ?? randomUUID();
    const incidentId = `INC-${Date.now().toString().slice(-6)}`;
    const now = new Date().toISOString();

    // Extract basic target file or fallback
    const fileMatch = params.rawText.match(/(?:src\/[a-zA-Z0-9_\-\/.]+\.ts)/);
    const affectedPath = fileMatch ? fileMatch[0] : 'src/auth.ts';

    const patchDiff = `--- a/${affectedPath}\n+++ b/${affectedPath}\n@@ -24,2 +24,2 @@\n- return session.token.expiresAt;\n+ return session?.token?.expiresAt ?? 0;`;
    const patches = [
      {
        path: affectedPath,
        action: 'MODIFY' as const,
        patchDiff
      }
    ];
    const diffHash = computeDiffHash(patches);

    const riskScore = 12;
    const riskReport: RiskReport = {
      riskScore,
      riskLevel: calculateRiskLevel(riskScore),
      blastRadius: [affectedPath],
      testsImpacted: ['test/auth.test.ts'],
      rollbackStrategy: 'Revert single commit, zero database migration impact',
      safetyGuarantees: ['Backward compatible API', 'Non-breaking session return type']
    };

    const spec: RemediationSpec = {
      id: `spec_${incidentId.toLowerCase()}`,
      incidentId,
      createdAt: now,
      targetRepository: 'owner/devpulse-demo',
      baseBranch: 'main',
      targetBranch: `devpulse/fix-${incidentId.toLowerCase()}`,
      errorSignature: params.rawText.slice(0, 120).trim(),
      rootCause: 'Uncaught null/undefined token dereference in session payload',
      patches,
      diffHash,
      riskReport,
      verificationCommands: ['npm test', 'npm run lint'],
      status: 'PROPOSED'
    };

    spec.specHash = computeSpecHash(spec);

    // Register ephemeral approval challenge bound to the exact specHash
    const challenge = this.challengeTracker.createChallenge({
      specId: spec.id,
      specHash: spec.specHash,
      allowedMaintainerIds: this.maintainerAllowlist
    });

    const formattedRoomMessage = [
      `### 🔍 [SENTINEL] Incident Investigation Report: ${incidentId}`,
      `- **Root Cause:** ${spec.rootCause}`,
      `- **Target File:** \`${affectedPath}\``,
      `- **Proposed Fix:**`,
      '```diff',
      patchDiff,
      '```',
      `- **Risk Report:** Score **${riskReport.riskScore}/100** (${riskReport.riskLevel}) | Blast Radius: \`${affectedPath}\``,
      `---`,
      `🛑 **Mandatory Human-in-the-Loop Approval Required**`,
      `To authorize remediation, reply in this room with:`,
      `\`@devpulse approve ${challenge.challengeId}\` *(Expires in 5 minutes)*`
    ].join('\n');

    if (this.auditLogger) {
      await this.auditLogger.log({
        actor: { type: 'SENTINEL', id: this.agentId, name: 'Sentinel' },
        action: 'INVESTIGATION_COMPLETED',
        incidentId,
        specId: spec.id,
        payload: {
          correlationId,
          challengeId: challenge.challengeId,
          specHash: spec.specHash,
          riskScore: riskReport.riskScore,
          affectedPath
        }
      });
    }

    return {
      incidentId,
      spec,
      riskReport,
      challenge,
      formattedRoomMessage
    };
  }

  /**
   * Generates a comprehensive, evidence-grounded investigation report
   * with decoupled confidence and risk, and evidence-based impact assessment.
   * Strictly DOES NOT create an approval challenge.
   */
  public async generateInvestigationReport(params: {
    rawText: string;
    senderId?: string | undefined;
    roomId?: string | undefined;
    correlationId?: string | undefined;
    incidentId?: string | undefined;
  }): Promise<InvestigationReport> {
    const correlationId = params.correlationId ?? randomUUID();
    const incidentId = params.incidentId ?? `INC-${Date.now().toString().slice(-6)}`;
    const timestamp = new Date().toISOString();

    // 1. Diagnostic Pipeline (Sub-Stage 4.1)
    const parsedTrace = parseStackTrace(params.rawText);
    const classification = classifyIncident(params.rawText, parsedTrace);
    const diagnosis = diagnoseIncident(params.rawText, classification, parsedTrace);

    // 2. Impact & Risk Evaluation (Sub-Stage 4.2)
    const impact = assessImpact(params.rawText, parsedTrace, classification);
    const riskEvaluation = evaluateRisk(params.rawText, classification, parsedTrace, impact);

    // 3. Synthesis & Markdown Report Generation (No Approval Challenge Created)
    const report = buildInvestigationReport({
      incidentId,
      timestamp,
      classification,
      diagnosis,
      riskEvaluation,
      impact
    });

    // 4. Audit Logging (Append-Only, Tamper-Evident)
    if (this.auditLogger) {
      await this.auditLogger.log({
        actor: { type: 'SENTINEL', id: this.agentId, name: 'Sentinel' },
        action: 'INVESTIGATION_REPORTED',
        incidentId,
        payload: {
          correlationId,
          incidentCategory: classification.category,
          evidenceCompleteness: classification.evidenceCompleteness,
          diagnosticConfidence: diagnosis.diagnosticConfidence,
          riskScore: riskEvaluation.riskScore,
          riskLevel: riskEvaluation.riskLevel,
          blastRadius: impact.classification,
          affectedComponents: impact.affectedComponents,
          confirmedFactsCount: diagnosis.confirmedFacts.length,
          hypothesesCount: diagnosis.hypotheses.length,
          appliedModifiers: riskEvaluation.appliedModifiers.map((m) => m.name)
        }
      });
    }

    return report;
  }

  /**
   * Dispatches an approved remediation task to the Runner agent.
   */
  public createTaskRequest(params: {
    spec: RemediationSpec;
    challengeId: string;
    approvedBy: string;
    correlationId: string;
  }): TaskRequestMessage {
    return {
      id: randomUUID(),
      type: 'TASK_REQUEST',
      correlationId: params.correlationId,
      timestamp: new Date().toISOString(),
      senderAgentId: this.agentId,
      targetAgentId: this.runnerAgentId,
      hopCount: 1, // Sentinel -> Runner is hop 1
      spec: params.spec,
      challengeId: params.challengeId,
      approvedBy: params.approvedBy,
      approvedAt: new Date().toISOString()
    };
  }
}
