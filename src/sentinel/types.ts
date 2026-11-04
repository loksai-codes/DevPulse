import { z } from 'zod';
import { RiskReport, RiskLevel } from '../types/risk-report.js';

export const EvidenceCompletenessSchema = z.enum(['COMPLETE', 'PARTIAL', 'INSUFFICIENT']);
export type EvidenceCompleteness = z.infer<typeof EvidenceCompletenessSchema>;

export const IncidentCategorySchema = z.enum([
  'RUNTIME_EXCEPTION',
  'BUILD_FAILURE',
  'TEST_FAILURE',
  'PRODUCTION_ALERT',
  'UNRECOGNIZED_ERROR'
]);
export type IncidentCategory = z.infer<typeof IncidentCategorySchema>;

export const FindingTypeSchema = z.enum(['CONFIRMED_FACT', 'HYPOTHESIS', 'RECOMMENDATION']);
export type FindingType = z.infer<typeof FindingTypeSchema>;

export const FindingSchema = z.object({
  id: z.string().min(1),
  type: FindingTypeSchema,
  description: z.string().min(1),
  evidenceSource: z.string().min(1, 'Evidence source must be explicitly documented'),
  file: z.string().optional(),
  line: z.number().int().positive().optional(),
  column: z.number().int().positive().optional(),
  confidence: z.number().min(0).max(1),
  uncertaintyReasons: z.array(z.string())
});
export type Finding = z.infer<typeof FindingSchema>;

export interface ParsedStackFrame {
  raw: string;
  file: string;
  line?: number | undefined;
  column?: number | undefined;
  functionName?: string | undefined;
  isProjectSource: boolean;
  isDependency: boolean;
  isRuntimeInternal: boolean;
}

export interface ParsedStackTrace {
  errorType?: string | undefined;
  errorMessage?: string | undefined;
  frames: ParsedStackFrame[];
  candidateCulpritFrame?: ParsedStackFrame | undefined;
  hasApplicationFrame: boolean;
}

export interface IncidentClassification {
  category: IncidentCategory;
  evidenceCompleteness: EvidenceCompleteness;
  summary: string;
  extractedErrorType?: string | undefined;
  extractedMessage?: string | undefined;
}

export interface InvestigationDiagnosis {
  incidentCategory: IncidentCategory;
  evidenceCompleteness: EvidenceCompleteness;
  rawErrorSignature: string;
  errorType?: string | undefined;
  errorMessage?: string | undefined;
  candidateCulpritFrame?: ParsedStackFrame | undefined;
  stackFrames: ParsedStackFrame[];
  findings: Finding[];
  confirmedFacts: string[];
  hypotheses: string[];
  diagnosticConfidence: number; // 0.0 to 1.0
  unresolvedQuestions: string[];
  limitations: string[];
}

export const BlastRadiusTypeSchema = z.enum(['KNOWN', 'ESTIMATED', 'UNKNOWN']);
export type BlastRadiusType = z.infer<typeof BlastRadiusTypeSchema>;

export interface EvidenceBasedImpact {
  classification: BlastRadiusType;
  affectedComponents: string[];
  affectedServices: string[];
  observedFailures: string[];
  evidenceSummary: string;
  unverifiedAssumptions: string[];
}

export interface RiskModifier {
  name: string;
  scoreChange: number;
  evidenceSource: string;
}

export interface RiskEvaluationResult {
  riskScore: number;
  riskLevel: RiskLevel;
  baseScore: number;
  appliedModifiers: RiskModifier[];
  riskReport: RiskReport;
}

export interface InvestigationReport {
  incidentId: string;
  timestamp: string;
  summary: string;
  classification: IncidentClassification;
  diagnosis: InvestigationDiagnosis;
  riskEvaluation: RiskEvaluationResult;
  impact: EvidenceBasedImpact;
  nextSteps: string[];
  formattedMarkdown: string;
}

