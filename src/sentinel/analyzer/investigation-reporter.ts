import {
  InvestigationReport,
  InvestigationDiagnosis,
  IncidentClassification,
  EvidenceBasedImpact,
  RiskEvaluationResult,
  HistoricalPrecedentSummary
} from '../types.js';

/**
 * Synthesizes the structured InvestigationReport and formats the Switch Room Markdown.
 * Clearly separates confirmed facts, hypotheses, and recommendations.
 * Strictly avoids automatically creating approval challenges.
 * Enforces diagnostic independence: historical precedents are included strictly for contextual intelligence.
 */
export function buildInvestigationReport(params: {
  incidentId: string;
  timestamp: string;
  classification: IncidentClassification;
  diagnosis: InvestigationDiagnosis;
  riskEvaluation: RiskEvaluationResult;
  impact: EvidenceBasedImpact;
  historicalPrecedents?: HistoricalPrecedentSummary[] | undefined;
  historicalPrecedentsNotice?: string | undefined;
}): InvestigationReport {
  const {
    incidentId,
    timestamp,
    classification,
    diagnosis,
    riskEvaluation,
    impact,
    historicalPrecedents = [],
    historicalPrecedentsNotice
  } = params;

  // 1. Synthesize recommended next investigative steps
  const nextSteps: string[] = [];

  if (classification.evidenceCompleteness === 'INSUFFICIENT') {
    nextSteps.push('Gather full application logs or unhandled exception stack traces from the monitoring system.');
    nextSteps.push('Correlate incident timestamp with recent service deployments or configuration changes.');
  } else {
    if (diagnosis.candidateCulpritFrame?.file) {
      nextSteps.push(`Inspect caller arguments and state preceding ${diagnosis.candidateCulpritFrame.file}${diagnosis.candidateCulpritFrame.line ? `:${diagnosis.candidateCulpritFrame.line}` : ''}.`);
    }
    if (impact.classification !== 'KNOWN') {
      nextSteps.push('Verify whether downstream API consumers or background workers observed related error spikes.');
    }
    nextSteps.push('Reproduce failure in isolated local environment using the observed error input.');
  }

  const summary = `${classification.category} in ${impact.affectedComponents[0] || 'unknown component'} (Risk: ${riskEvaluation.riskLevel} ${riskEvaluation.riskScore}/100, Diagnostic Confidence: ${(diagnosis.diagnosticConfidence * 100).toFixed(0)}%)`;

  // 2. Format Switch Room Markdown
  const markdownLines: string[] = [
    `### 🔍 [SENTINEL INVESTIGATION REPORT] \`${incidentId}\``,
    `> **Summary:** ${summary}`,
    ``,
    `| Metric | Value | Provenance / Evidence Basis |`,
    `| :--- | :--- | :--- |`,
    `| **Category** | \`${classification.category}\` | Input pattern & exception classification |`,
    `| **Evidence Quality** | \`${classification.evidenceCompleteness}\` | Header + stack frame completeness |`,
    `| **Diagnostic Confidence** | **${(diagnosis.diagnosticConfidence * 100).toFixed(0)}%** | Strictly evidence-grounded (independent of risk) |`,
    `| **Operational Risk** | **${riskEvaluation.riskScore}/100** (\`${riskEvaluation.riskLevel}\`) | Base: ${riskEvaluation.baseScore} + Evidence Modifiers: ${riskEvaluation.appliedModifiers.reduce((acc, m) => acc + m.scoreChange, 0)} |`,
    `| **Blast Radius** | \`${impact.classification}\` | ${impact.evidenceSummary} |`,
    ``,
    `#### 📌 Confirmed Facts`,
    diagnosis.confirmedFacts.length > 0
      ? diagnosis.confirmedFacts.map((fact) => `- ${fact}`).join('\n')
      : '- No deterministic facts could be verified from the provided log excerpt.',
    ``,
    `#### 💡 Root-Cause Hypotheses`,
    diagnosis.hypotheses.length > 0
      ? diagnosis.hypotheses.map((hyp) => `- ${hyp}`).join('\n')
      : '- Evidence is insufficient to formulate a plausible root-cause hypothesis.',
    ``,
    `#### 🔍 Candidate Culprit Location`,
    diagnosis.candidateCulpritFrame
      ? `- \`${diagnosis.candidateCulpritFrame.file}${diagnosis.candidateCulpritFrame.line ? `:${diagnosis.candidateCulpritFrame.line}` : ''}\` *(Candidate location: failure execution point, not confirmed root cause)*`
      : '- No candidate application frame identified.',
    ``,
    `#### 🌐 Impact Assessment`,
    `- **Affected Components:** ${impact.affectedComponents.map((c) => `\`${c}\``).join(', ')}`,
    impact.affectedServices.length > 0
      ? `- **Corroborated Services:** ${impact.affectedServices.map((s) => `\`${s}\``).join(', ')}`
      : `- **Corroborated Services:** None explicitly identified in log`,
    `- **Observed Failures:** ${impact.observedFailures.join(', ')}`,
    impact.unverifiedAssumptions.length > 0
      ? `- **Unverified Assumptions:** ${impact.unverifiedAssumptions.join('; ')}`
      : '',
    ``,
    `#### ❓ Missing Information & Limitations`,
    diagnosis.limitations.length > 0
      ? diagnosis.limitations.map((lim) => `- ⚠️ ${lim}`).join('\n')
      : '- Complete stack trace and project location available.',
    diagnosis.unresolvedQuestions.length > 0
      ? diagnosis.unresolvedQuestions.map((q) => `- ❓ ${q}`).join('\n')
      : '',
    ``,
    `#### 🧭 Recommended Next Investigative Steps`,
    nextSteps.map((step, idx) => `${idx + 1}. ${step}`).join('\n'),
    ``,
    `#### 📚 Historical Precedents & Outcome Intelligence`,
    `> *Contextual Intelligence Only: Historical precedents provide contextual reference and never prove current root cause, blast radius, or remediation safety.*`,
    historicalPrecedentsNotice ? `*(Notice: ${historicalPrecedentsNotice})*` : '',
    historicalPrecedents.length > 0
      ? historicalPrecedents
          .map((p) => {
            const out = p.historicalOutcome;
            const lines: string[] = [
              `- **Precedent:** \`${p.incidentId}\` — [${p.matchType} | Match Score: ${(p.overallScore * 100).toFixed(0)}%] — Status: \`${out.currentStatus}\``,
              `  - **Repository:** \`${p.canonicalRepository}\``,
              `  - **Relevance:** ${p.relevanceExplanation}`,
              `  - **Prior Root Cause:** ${out.rootCause}`,
              `  - **Prior Fix:** ${out.fixSummary}`,
              `  - **PR Reference:** ${out.prLink || '*(None recorded)*'}`,
              `  - **Provenance:** \`${out.evidenceProvenanceSummary.verificationType}\`${out.evidenceProvenanceSummary.displayLabel ? ` (${out.evidenceProvenanceSummary.displayLabel})` : ''}`
            ];

            // Mandatory regression warnings
            if (out.isRegressed) {
              lines.push(
                `  > ⚠️ **CRITICAL WARNING:** This historical resolution subsequently **REGRESSED** in production (Advisory: \`${out.recommendationAdvisory}\`). Do NOT reuse as a proven fix.`
              );
            } else if (out.hasHistoricalRegression) {
              lines.push(
                `  > ⚠️ **HISTORICAL REGRESSION WARNING:** This incident experienced a prior regression in its lifecycle before resolution was verified with fresh evidence.`
              );
            } else if (out.currentStatus === 'PARTIAL_RESOLUTION') {
              lines.push(
                `  > ℹ️ **PARTIAL MITIGATION ONLY:** Remediation provides partial stabilization; remaining defects were not fully resolved.`
              );
            } else if (out.currentStatus === 'UNVERIFIED_PROPOSAL') {
              lines.push(
                `  > ℹ️ **UNVERIFIED PROPOSAL:** This historical proposal was never independently verified or confirmed.`
              );
            }

            if (out.evidenceProvenanceSummary.missingOrUnavailableEvidence.length > 0) {
              lines.push(
                `  - **Missing Historical Evidence:** ${out.evidenceProvenanceSummary.missingOrUnavailableEvidence.join('; ')}`
              );
            }

            return lines.join('\n');
          })
          .join('\n\n')
      : !historicalPrecedentsNotice
      ? '*(No similar historical incidents found in repository memory)*'
      : '',
    ``,
    `---`,
    `*Notice: Investigation report published for engineering review. No approval challenge or patch was automatically generated.*`
  ];

  const formattedMarkdown = markdownLines.filter((line) => line !== '').join('\n');

  return {
    incidentId,
    timestamp,
    summary,
    classification,
    diagnosis,
    riskEvaluation,
    impact,
    historicalPrecedents,
    ...(historicalPrecedentsNotice ? { historicalPrecedentsNotice } : {}),
    nextSteps,
    formattedMarkdown
  };
}

