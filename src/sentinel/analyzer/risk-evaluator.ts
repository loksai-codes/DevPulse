import {
  RiskReport,
  RiskLevel,
  calculateRiskLevel
} from '../../types/risk-report.js';
import {
  IncidentClassification,
  ParsedStackTrace,
  EvidenceBasedImpact,
  RiskModifier,
  RiskEvaluationResult
} from '../types.js';

/**
 * Deterministic Risk Evaluator.
 * Implements an exact, non-variable mathematical scoring formula.
 * Identical inputs produce strictly identical outputs.
 * Never infers risk from filenames or directory names alone.
 */
export function evaluateRisk(
  rawText: string,
  classification: IncidentClassification,
  _parsedTrace: ParsedStackTrace,
  impact: EvidenceBasedImpact
): RiskEvaluationResult {
  // 1. Exact Base Score by Category
  let baseScore = 10;
  switch (classification.category) {
    case 'PRODUCTION_ALERT':
      baseScore = 65;
      break;
    case 'RUNTIME_EXCEPTION':
      baseScore = 40;
      break;
    case 'TEST_FAILURE':
      baseScore = 20;
      break;
    case 'BUILD_FAILURE':
      baseScore = 15;
      break;
    case 'UNRECOGNIZED_ERROR':
      baseScore = 10;
      break;
  }

  // 2. Traceable Evidence Modifiers (Strictly based on explicit evidence, never filenames)
  const appliedModifiers: RiskModifier[] = [];

  // Modifier A: Production 5xx / Outage Evidence
  const outageMatch = rawText.match(/\b(5\d\d\b|outage|cluster down|crash loop|service unavailable)/i);
  if (outageMatch) {
    appliedModifiers.push({
      name: 'PRODUCTION_OUTAGE_OBSERVED',
      scoreChange: 20,
      evidenceSource: outageMatch[0].trim()
    });
  }

  // Modifier B: Security, Authentication, or Corruption Evidence in Error Text
  const securityMatch = rawText.match(/\b(unauthorized|forbidden|token invalid|jwt expired|data loss|corrupted)/i);
  if (securityMatch) {
    appliedModifiers.push({
      name: 'SECURITY_OR_DATA_INTEGRITY_FLAG',
      scoreChange: 15,
      evidenceSource: securityMatch[0].trim()
    });
  }

  // Modifier C: Isolated Pre-Production Defect (Build or Test Failure)
  if (classification.category === 'BUILD_FAILURE' || classification.category === 'TEST_FAILURE') {
    appliedModifiers.push({
      name: 'PRE_PRODUCTION_ISOLATION',
      scoreChange: -10,
      evidenceSource: `Incident classified as pre-production '${classification.category}'`
    });
  }

  // 3. Compute Exact Clamped Score
  const modifierSum = appliedModifiers.reduce((acc, m) => acc + m.scoreChange, 0);
  const rawScore = baseScore + modifierSum;
  const riskScore = Math.max(0, Math.min(100, Math.round(rawScore)));
  const riskLevel: RiskLevel = calculateRiskLevel(riskScore);

  // 4. Synthesize RiskReport conforming strictly to RiskReportSchema
  // When blast radius is UNKNOWN, output exactly ['UNKNOWN'] without explanatory prose
  const blastRadius = impact.classification === 'UNKNOWN' || impact.affectedComponents[0] === 'UNKNOWN'
    ? ['UNKNOWN']
    : impact.affectedComponents;

  const targetComponent = blastRadius[0] || 'UNKNOWN';
  const impactedTests = targetComponent !== 'UNKNOWN'
    ? [`tests/${targetComponent.replace(/\.[^/.]+$/, '')}.test.ts`]
    : [];

  const riskReport: RiskReport = {
    riskScore,
    riskLevel,
    blastRadius,
    testsImpacted: impactedTests,
    rollbackStrategy: targetComponent !== 'UNKNOWN'
      ? `Revert single commit affecting '${targetComponent}'`
      : 'Maintain current deployed release; do not deploy unverified code',
    complianceNotes: `Evidence impact: ${impact.classification}. Diagnostic confidence separate from risk.`,
    safetyGuarantees: [
      'Diagnostic evaluation only; zero active mutation',
      'No approval challenge automatically generated'
    ]
  };

  return {
    riskScore,
    riskLevel,
    baseScore,
    appliedModifiers,
    riskReport
  };
}

