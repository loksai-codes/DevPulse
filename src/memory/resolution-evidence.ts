import { z } from 'zod';
import { createHash } from 'node:crypto';
import { CanonicalRepositorySchema } from './types.js';
import { sanitizeAuditPayload } from '../utils/crypto.js';

/**
 * Trusted and recognized evidence origins.
 */
export const EvidenceSourceSchema = z.enum([
  'GITHUB_API',             // GitHub REST / GraphQL API
  'GIT_CLI',                // Local or runner git command execution
  'CI_CD_PIPELINE',         // CI/CD workflow runner (e.g., GitHub Actions, Jenkins)
  'OBSERVABILITY_SYSTEM',   // Datadog, Prometheus, Grafana, CloudWatch, Sentry
  'SWITCH_ROOM',            // Verified human maintainer over Switch Console
  'USER_ASSERTION'          // Unverified assertion submitted by user or external input
]);
export type EvidenceSource = z.infer<typeof EvidenceSourceSchema>;

/**
 * Quality classification of evidence verification.
 */
export const EvidenceVerificationTypeSchema = z.enum([
  'INDEPENDENTLY_VERIFIED', // Autonomously confirmed via trusted API, runner, or pipeline
  'USER_PROVIDED'           // Asserted by human actor or unauthenticated payload
]);
export type EvidenceVerificationType = z.infer<typeof EvidenceVerificationTypeSchema>;

/**
 * Common Evidence Provenance Contract.
 * Enforces traceable origin, cryptographic hash, and truthfulness of independent verification.
 */
export const EvidenceProvenanceSchema = z
  .object({
    source: EvidenceSourceSchema,
    sourceReference: z.string().min(1, 'sourceReference must identify the origin (e.g. PR URL, run ID, commit ref)'),
    capturedAt: z.string().datetime({ message: 'capturedAt must be an ISO-8601 string' }),
    verificationType: EvidenceVerificationTypeSchema,
    evidenceHash: z.string().regex(/^[a-f0-9]{64}$/i, 'evidenceHash must be a 64-character SHA-256 hex string'),
    capturedBy: z
      .object({
        type: z.enum(['HUMAN', 'SENTINEL', 'SYSTEM']),
        id: z.string().min(1),
        name: z.string().min(1)
      })
      .optional()
  })
  .refine(
    (prov) => {
      // Do not claim independent verification without a trusted evidence source
      if (prov.verificationType === 'INDEPENDENTLY_VERIFIED') {
        return prov.source !== 'USER_ASSERTION';
      }
      return true;
    },
    {
      message: "Evidence with source 'USER_ASSERTION' cannot claim 'INDEPENDENTLY_VERIFIED' verificationType"
    }
  );
export type EvidenceProvenance = z.infer<typeof EvidenceProvenanceSchema>;

/**
 * 1. Merged PR Evidence Schema
 */
export const MergedPREvidenceSchema = z.object({
  prNumber: z.number().int().positive('prNumber must be a positive integer'),
  prUrl: z.string().url('prUrl must be a valid URL'),
  baseBranch: z.string().min(1, 'baseBranch cannot be empty'),
  mergeCommitSha: z.string().regex(/^[a-f0-9]{40,64}$/i, 'mergeCommitSha must be a 40-64 character hexadecimal commit SHA'),
  mergedAt: z.string().datetime({ message: 'mergedAt must be an ISO-8601 string' }),
  mergedBy: z.string().min(1, 'mergedBy identifier cannot be empty'),
  provenance: EvidenceProvenanceSchema
});
export type MergedPREvidence = z.infer<typeof MergedPREvidenceSchema>;

/**
 * 2. Regression Test Evidence Schema
 * Strictly enforces consistent test count arithmetic and non-negative values.
 */
export const RegressionTestEvidenceSchema = z
  .object({
    testSuiteName: z.string().min(1, 'testSuiteName cannot be empty'),
    command: z.string().min(1, 'test command cannot be empty'),
    executedAt: z.string().datetime({ message: 'executedAt must be an ISO-8601 string' }),
    durationMs: z.number().int().nonnegative('durationMs cannot be negative'),
    totalTests: z.number().int().nonnegative('totalTests cannot be negative'),
    passedTests: z.number().int().nonnegative('passedTests cannot be negative'),
    failedTests: z.number().int().nonnegative('failedTests cannot be negative'),
    skippedTests: z.number().int().nonnegative('skippedTests cannot be negative'),
    outputLogHash: z.string().regex(/^[a-f0-9]{64}$/i, 'outputLogHash must be a 64-character SHA-256 hex string'),
    provenance: EvidenceProvenanceSchema
  })
  .refine(
    (test) => test.totalTests === test.passedTests + test.failedTests + test.skippedTests,
    {
      message: 'Inconsistent test counts: totalTests must strictly equal passedTests + failedTests + skippedTests'
    }
  );
export type RegressionTestEvidence = z.infer<typeof RegressionTestEvidenceSchema>;

/**
 * Evaluates whether regression test evidence demonstrates genuine passing execution.
 * Rules:
 * - Consistent test count arithmetic: totalTests === passedTests + failedTests + skippedTests
 * - failedTests must be strictly 0
 * - passedTests must be strictly greater than 0
 * - Skipped tests remain visible as an independent metric and are NEVER classified as passed
 * - Skipped-only runs or empty test runs (passedTests === 0) do not establish recovery
 */
export function isRegressionTestExecutionSuccessful(evidence: RegressionTestEvidence): boolean {
  // 1. Arithmetic consistency check
  if (evidence.totalTests !== evidence.passedTests + evidence.failedTests + evidence.skippedTests) {
    return false;
  }
  // 2. Must have zero failures
  if (evidence.failedTests !== 0) return false;
  // 3. Must have at least one passed test (skipped-only or empty runs do not establish recovery)
  if (evidence.passedTests <= 0) return false;
  return true;
}

/**
 * 3. Resolution Confirmation Schema
 * Separates human confirmation from automated observability recovery evidence.
 */
export const HumanConfirmationSchema = z.object({
  actor: z.object({
    type: z.literal('HUMAN'),
    id: z.string().min(1),
    name: z.string().min(1)
  }),
  confirmedAt: z.string().datetime({ message: 'confirmedAt must be an ISO-8601 string' }),
  notes: z.string().min(1, 'Human confirmation notes cannot be empty')
});
export type HumanConfirmation = z.infer<typeof HumanConfirmationSchema>;

export const ObservabilityRecoveryEvidenceSchema = z.object({
  metricOrLogRef: z.string().min(1, 'metricOrLogRef (dashboard URL, query, or log stream) is required'),
  observedAt: z.string().datetime({ message: 'observedAt must be an ISO-8601 string' }),
  query: z.string().optional(),
  sampleProof: z.string().min(1, 'sampleProof (structured metrics, zero 5xx error rate proof) is required'),
  provenance: EvidenceProvenanceSchema
});
export type ObservabilityRecoveryEvidence = z.infer<typeof ObservabilityRecoveryEvidenceSchema>;

export const ResolutionConfirmationSchema = z
  .object({
    confirmedAt: z.string().datetime({ message: 'confirmedAt must be an ISO-8601 string' }),
    humanConfirmation: HumanConfirmationSchema.optional(),
    observabilityEvidence: ObservabilityRecoveryEvidenceSchema.optional(),
    freeTextDescription: z.string().optional(),
    provenance: EvidenceProvenanceSchema
  })
  .refine(
    (conf) => {
      // Rule: A free-text recovery description alone must never independently establish verified recovery
      if (conf.provenance.verificationType === 'INDEPENDENTLY_VERIFIED') {
        return Boolean(conf.observabilityEvidence);
      }
      return Boolean(conf.humanConfirmation || conf.observabilityEvidence);
    },
    {
      message: 'A free-text recovery description alone cannot establish verified recovery. Valid observability evidence or human confirmation is required.'
    }
  );
export type ResolutionConfirmation = z.infer<typeof ResolutionConfirmationSchema>;

/**
 * 4. Diff Integrity Contract
 * Binds verification evidence to the exact remediation specification.
 * Distinguishes proposed diff hash from actual merged diff hash.
 */
export const DiffIntegrityEvidenceSchema = z
  .object({
    proposedDiffHash: z.string().regex(/^[a-f0-9]{64}$/i, 'proposedDiffHash must be a 64-character SHA-256 hex string'),
    actualMergedDiffHash: z.string().regex(/^[a-f0-9]{64}$/i, 'actualMergedDiffHash must be a 64-character SHA-256 hex string'),
    isReconciled: z.boolean().default(false),
    reconciliationReason: z.string().optional(),
    reconciledBy: z
      .object({
        type: z.enum(['HUMAN', 'SENTINEL', 'SYSTEM']),
        id: z.string().min(1),
        name: z.string().min(1)
      })
      .optional()
  })
  .refine(
    (diff) => {
      // If hashes match exactly, no reconciliation needed
      if (diff.proposedDiffHash.toLowerCase() === diff.actualMergedDiffHash.toLowerCase()) {
        return true;
      }
      // If hashes differ, they must be explicitly reconciled with explanation and acting authority
      return (
        diff.isReconciled === true &&
        Boolean(diff.reconciliationReason && diff.reconciliationReason.trim().length > 0) &&
        Boolean(diff.reconciledBy)
      );
    },
    {
      message: 'Mismatched proposed and merged diff hashes require explicit reconciliation (isReconciled=true, reconciliationReason, and reconciledBy)'
    }
  );
export type DiffIntegrityEvidence = z.infer<typeof DiffIntegrityEvidenceSchema>;

/**
 * 5. Regression Evidence Schema
 */
export const RegressionEvidenceSchema = z.object({
  incidentId: z.string().min(1, 'incidentId cannot be empty'),
  canonicalRepository: CanonicalRepositorySchema,
  detectedAt: z.string().datetime({ message: 'detectedAt must be an ISO-8601 string' }),
  failureReason: z.string().min(1, 'failureReason must describe the observed regression'),
  corroboratingIncidentId: z.string().optional(),
  provenance: EvidenceProvenanceSchema
});
export type RegressionEvidence = z.infer<typeof RegressionEvidenceSchema>;

/**
 * 6. Partial Resolution Evidence Schema
 */
export const PartialResolutionEvidenceSchema = z.object({
  incidentId: z.string().min(1, 'incidentId cannot be empty'),
  canonicalRepository: CanonicalRepositorySchema,
  mitigatedAt: z.string().datetime({ message: 'mitigatedAt must be an ISO-8601 string' }),
  mitigationScope: z.string().min(1, 'mitigationScope must describe what was mitigated'),
  remainingDefects: z.string().min(1, 'remainingDefects must describe unresolved root causes or pending work'),
  provenance: EvidenceProvenanceSchema
});
export type PartialResolutionEvidence = z.infer<typeof PartialResolutionEvidenceSchema>;

/**
 * 7. Comprehensive Full Resolution Verification Bundle
 * Requires proof across all 4 pillars:
 * 1. Merged PR evidence
 * 2. Diff integrity evidence
 * 3. Passing regression test evidence
 * 4. Resolution confirmation evidence
 */
export const FullResolutionVerificationBundleSchema = z.object({
  incidentId: z.string().min(1, 'incidentId cannot be empty'),
  canonicalRepository: CanonicalRepositorySchema,
  pr: MergedPREvidenceSchema,
  diff: DiffIntegrityEvidenceSchema,
  regressionTests: RegressionTestEvidenceSchema,
  confirmation: ResolutionConfirmationSchema
});
export type FullResolutionVerificationBundle = z.infer<typeof FullResolutionVerificationBundleSchema>;

/**
 * 8. Unverified Proposal Evidence Schema
 * Staged or iterated fix proposal (used for initial state or fresh iterations after regression).
 */
export const UnverifiedProposalEvidenceSchema = z.object({
  incidentId: z.string().min(1, 'incidentId cannot be empty'),
  canonicalRepository: CanonicalRepositorySchema,
  proposedDiffHash: z.string().regex(/^[a-f0-9]{64}$/i, 'proposedDiffHash must be a 64-character SHA-256 hex string'),
  proposalSummary: z.string().min(1, 'proposalSummary cannot be empty'),
  stagedPrUrl: z.string().url().optional(),
  proposedAt: z.string().datetime({ message: 'proposedAt must be an ISO-8601 string' }),
  provenance: EvidenceProvenanceSchema
});
export type UnverifiedProposalEvidence = z.infer<typeof UnverifiedProposalEvidenceSchema>;

/**
 * Extensible Integration Interface Stubs (Contracts only, no external calls).
 */
export interface GitHubEvidenceProvider {
  fetchPRMergeEvidence(repo: string, prNumber: number): Promise<MergedPREvidence>;
}

export interface ObservabilityEvidenceProvider {
  fetchRecoveryMetrics(query: string, timeRange: { start: string; end: string }): Promise<ObservabilityRecoveryEvidence>;
}

/**
 * Computes a deterministic SHA-256 fingerprint of the sanitized evidence payload.
 *
 * IMPORTANT CAVEATS & SCOPE:
 * - This hash is computed on the CANONICAL SANITIZED representation of the payload
 *   (where sensitive credentials, keys, and tokens have been redacted and keys sorted).
 * - It does NOT represent the hash of the original raw evidence prior to sanitization.
 * - It does NOT provide cryptographic proof of source authenticity or non-repudiation;
 *   authenticity must be established by the underlying EvidenceSource (e.g. GitHub API, CI/CD runner)
 *   and EvidenceVerificationType.
 */
export function computeEvidenceHash(payload: unknown): string {
  const sanitized = sanitizeAuditPayload(payload);
  const serialized = JSON.stringify(sanitized, Object.keys(sanitized as object || {}).sort());
  return createHash('sha256').update(serialized, 'utf8').digest('hex');
}

