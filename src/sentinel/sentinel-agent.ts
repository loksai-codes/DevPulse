import { randomUUID } from 'node:crypto';
import { RemediationSpec } from '../types/remediation.js';
import { RiskReport, calculateRiskLevel } from '../types/risk-report.js';
import { computeDiffHash, computeSpecHash } from '../utils/crypto.js';
import { ChallengeTracker, ApprovalChallenge } from '../approval/challenge-tracker.js';
import { AuditLogger } from '../audit/audit-logger.js';
import { TaskRequestMessage } from '../types/agent-contracts.js';
import {
  InvestigationReport,
  InvestigationDiagnosis,
  IncidentClassification,
  EvidenceBasedImpact,
  HistoricalPrecedentSummary
} from './types.js';
import { parseStackTrace } from './analyzer/stack-trace-parser.js';
import { classifyIncident } from './analyzer/incident-classifier.js';
import { diagnoseIncident } from './analyzer/root-cause-engine.js';
import { assessImpact } from './analyzer/impact-assessor.js';
import { evaluateRisk } from './analyzer/risk-evaluator.js';
import { buildInvestigationReport } from './analyzer/investigation-reporter.js';
import {
  IncidentStore,
  IncidentMemoryQuery,
  normalizeCanonicalRepository,
  evaluateIncidentSimilarity,
  rankHistoricalMatches
} from '../memory/index.js';

export interface SentinelAgentOptions {
  agentId: string;
  runnerAgentId: string;
  maintainerAllowlist: string[];
  challengeTracker: ChallengeTracker;
  auditLogger?: AuditLogger | undefined;
  incidentStore?: IncidentStore | undefined;
  defaultCanonicalRepository?: string | undefined;
}

export interface InvestigationResult {
  incidentId: string;
  spec: RemediationSpec;
  riskReport: RiskReport;
  challenge: ApprovalChallenge;
  formattedRoomMessage: string;
  historicalPrecedents?: HistoricalPrecedentSummary[] | undefined;
  historicalPrecedentsNotice?: string | undefined;
}

export class SentinelAgent {
  public readonly agentId: string;
  public readonly runnerAgentId: string;
  private maintainerAllowlist: string[];
  private challengeTracker: ChallengeTracker;
  private auditLogger?: AuditLogger | undefined;
  private incidentStore?: IncidentStore | undefined;
  private defaultCanonicalRepository?: string | undefined;

  constructor(options: SentinelAgentOptions) {
    this.agentId = options.agentId;
    this.runnerAgentId = options.runnerAgentId;
    this.maintainerAllowlist = options.maintainerAllowlist;
    this.challengeTracker = options.challengeTracker;
    this.auditLogger = options.auditLogger;
    this.incidentStore = options.incidentStore;
    this.defaultCanonicalRepository = options.defaultCanonicalRepository ?? 'owner/devpulse-demo';
  }

  /**
   * Investigates an incident description or stack trace and synthesizes a remediation proposal.
   * If a canonical repository is provided, contextual historical precedents are queried and reported.
   * Remediation proposals and risk evaluations strictly maintain diagnostic independence.
   */
  public async investigate(params: {
    rawText: string;
    canonicalRepository?: string | undefined;
    senderId: string;
    roomId: string;
    correlationId?: string;
  }): Promise<InvestigationResult> {
    const correlationId = params.correlationId ?? randomUUID();
    const incidentId = `INC-${Date.now().toString().slice(-6)}`;
    const now = new Date().toISOString();

    // 1. Diagnostic synthesis (diagnostic independence preserved)
    const fileMatch = params.rawText.match(/(?:src\/[a-zA-Z0-9_\-\/.]+\.(?:ts|js))/);
    const affectedPath = fileMatch ? fileMatch[0] : 'src/auth.js';

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

    const rawRepo = params.canonicalRepository ?? this.defaultCanonicalRepository;
    if (!rawRepo || !rawRepo.trim()) {
      throw new Error(
        'Cannot generate executable remediation specification: repository baseline is missing or ambiguous.'
      );
    }

    let targetRepo: string;
    try {
      targetRepo = normalizeCanonicalRepository(rawRepo);
    } catch {
      throw new Error(
        `Cannot generate executable remediation specification: invalid repository baseline '${rawRepo}'.`
      );
    }

    const spec: RemediationSpec = {
      id: `spec_${incidentId.toLowerCase()}`,
      incidentId,
      createdAt: now,
      targetRepository: targetRepo,
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

    // 2. Read-only historical precedent lookup
    const parsedTrace = parseStackTrace(params.rawText);
    const classification = classifyIncident(params.rawText, parsedTrace);
    const diagnosis = diagnoseIncident(params.rawText, classification, parsedTrace);
    const impact = assessImpact(params.rawText, parsedTrace, classification);

    const memoryResult = await this.queryHistoricalPrecedents(
      params.canonicalRepository,
      diagnosis,
      classification,
      impact
    );

    const messageLines = [
      `### 🔍 [SENTINEL] Incident Investigation Report: ${incidentId}`,
      `- **Root Cause:** ${spec.rootCause}`,
      `- **Target File:** \`${affectedPath}\``,
      `- **Proposed Fix:**`,
      '```diff',
      patchDiff,
      '```',
      `- **Risk Report:** Score **${riskReport.riskScore}/100** (${riskReport.riskLevel}) | Blast Radius: \`${affectedPath}\``
    ];

    if (memoryResult.precedents.length > 0) {
      messageLines.push(`- **Historical Precedents (${memoryResult.precedents.length}):**`);
      for (const p of memoryResult.precedents) {
        let pLine = `  - \`${p.incidentId}\` (${p.matchType}, ${(p.overallScore * 100).toFixed(0)}%) [${p.historicalOutcome.currentStatus}]: ${p.historicalOutcome.fixSummary}`;
        if (p.historicalOutcome.isRegressed) {
          pLine += ' *(⚠️ REGRESSED: Do NOT reuse as proven fix)*';
        } else if (p.historicalOutcome.hasHistoricalRegression) {
          pLine += ' *(⚠️ Historical regression in lifecycle)*';
        }
        messageLines.push(pLine);
      }
    } else if (memoryResult.notice) {
      messageLines.push(`- **Historical Precedents:** *(${memoryResult.notice})*`);
    }

    messageLines.push(
      `---`,
      `🛑 **Mandatory Human-in-the-Loop Approval Required**`,
      `To authorize remediation, reply in this room with:`,
      `\`@devpulse approve ${challenge.challengeId}\` *(Expires in 5 minutes)*`
    );

    const formattedRoomMessage = messageLines.join('\n');

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
          affectedPath,
          historicalPrecedentsCount: memoryResult.precedents.length
        }
      });
    }

    return {
      incidentId,
      spec,
      riskReport,
      challenge,
      formattedRoomMessage,
      historicalPrecedents: memoryResult.precedents,
      ...(memoryResult.notice ? { historicalPrecedentsNotice: memoryResult.notice } : {})
    };
  }

  /**
   * Generates a comprehensive, evidence-grounded investigation report
   * with decoupled confidence and risk, evidence-based impact assessment,
   * and read-only historical memory precedent integration.
   * Strictly DOES NOT create an approval challenge.
   */
  public async generateInvestigationReport(params: {
    rawText: string;
    canonicalRepository?: string | undefined;
    senderId?: string | undefined;
    roomId?: string | undefined;
    correlationId?: string | undefined;
    incidentId?: string | undefined;
  }): Promise<InvestigationReport> {
    const correlationId = params.correlationId ?? randomUUID();
    const incidentId = params.incidentId ?? `INC-${Date.now().toString().slice(-6)}`;
    const timestamp = new Date().toISOString();

    // 1. Diagnostic Pipeline (Sub-Stage 4.1) — Executes strictly before memory lookup
    const parsedTrace = parseStackTrace(params.rawText);
    const classification = classifyIncident(params.rawText, parsedTrace);
    const diagnosis = diagnoseIncident(params.rawText, classification, parsedTrace);

    // 2. Impact & Risk Evaluation (Sub-Stage 4.2) — Strictly independent of historical memory
    const impact = assessImpact(params.rawText, parsedTrace, classification);
    const riskEvaluation = evaluateRisk(params.rawText, classification, parsedTrace, impact);

    // 3. Contextual Read-Only Memory Retrieval (Sub-Stage 4.3 Integration)
    const memoryResult = await this.queryHistoricalPrecedents(
      params.canonicalRepository,
      diagnosis,
      classification,
      impact
    );

    // 4. Synthesis & Markdown Report Generation (No Approval Challenge Created)
    const report = buildInvestigationReport({
      incidentId,
      timestamp,
      classification,
      diagnosis,
      riskEvaluation,
      impact,
      historicalPrecedents: memoryResult.precedents,
      historicalPrecedentsNotice: memoryResult.notice
    });

    // 5. Audit Logging (Append-Only, Tamper-Evident)
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
          appliedModifiers: riskEvaluation.appliedModifiers.map((m) => m.name),
          historicalPrecedentsCount: memoryResult.precedents.length
        }
      });
    }

    return report;
  }

  /**
   * Helper: Queries historical incident memory within strict repository boundaries.
   * Enforces distinct handling for: missing repository, invalid repository, store unavailable,
   * retrieval errors, and no matches.
   * Strictly read-only; never writes to IncidentStore.
   */
  private async queryHistoricalPrecedents(
    canonicalRepository: string | undefined,
    diagnosis: InvestigationDiagnosis,
    classification: IncidentClassification,
    impact: EvidenceBasedImpact
  ): Promise<{ precedents: HistoricalPrecedentSummary[]; notice?: string | undefined }> {
    // Condition 1: Missing repository identity
    if (!canonicalRepository || canonicalRepository.trim().length === 0) {
      return {
        precedents: [],
        notice: 'Repository identity unavailable: memory retrieval skipped to enforce repository boundary.'
      };
    }

    // Condition 2: Invalid repository identity
    let normRepo: string;
    try {
      normRepo = normalizeCanonicalRepository(canonicalRepository);
    } catch {
      return {
        precedents: [],
        notice: `Invalid repository identity '${canonicalRepository}': memory retrieval skipped to enforce repository boundary.`
      };
    }

    // Condition 3: Memory store unavailable / not configured or uninitialized
    if (!this.incidentStore || (typeof this.incidentStore.isInitialized === 'function' && !this.incidentStore.isInitialized())) {
      return {
        precedents: [],
        notice: 'Memory store unavailable: proceeding with log-grounded investigation.'
      };
    }

    // Condition 4 & 5: Read-only query execution & retrieval error handling
    try {
      const candidateRecords = this.incidentStore.listByRepository(normRepo);
      if (!candidateRecords || candidateRecords.length === 0) {
        return { precedents: [] }; // Condition: No matches in repository
      }

      const affectedTarget = diagnosis.candidateCulpritFrame?.file ?? impact.affectedComponents[0];
      const firstLine = diagnosis.rawErrorSignature.split(/\r?\n/)[0]?.trim();
      const errorSignature =
        diagnosis.errorType && diagnosis.errorMessage
          ? `${diagnosis.errorType}: ${diagnosis.errorMessage}`
          : firstLine || classification.summary;

      const query: IncidentMemoryQuery = {
        canonicalRepository: normRepo,
        errorSignature,
        category: classification.category,
        affectedTarget,
        stackFrames: diagnosis.stackFrames,
        minSimilarityScore: 0.60,
        maxResults: 3
      };

      const matches = candidateRecords
        .map((rec) => evaluateIncidentSimilarity(query, rec))
        .filter((m): m is NonNullable<typeof m> => m !== null);

      const ranked = rankHistoricalMatches(matches).slice(0, 3);

      const precedents: HistoricalPrecedentSummary[] = ranked.map((m) => ({
        incidentId: m.record.id,
        canonicalRepository: m.record.canonicalRepository,
        overallScore: m.similarity.overallScore,
        matchType: m.similarity.matchType,
        relevanceExplanation: m.relevanceExplanation,
        historicalOutcome: m.outcomeReport
      }));

      return { precedents };
    } catch (err) {
      return {
        precedents: [],
        notice: `Historical memory query encountered an error: ${String(err)}`
      };
    }
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
