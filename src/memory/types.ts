import { z } from 'zod';
import { IncidentOutcomeSchema } from '../types/incident.js';
import { IncidentCategorySchema, ParsedStackFrame } from '../sentinel/types.js';

/**
 * Validates a canonical repository identifier.
 * Rejects:
 * - Path traversal segments ('..', '../repo', 'owner/..')
 * - Dot-only segments ('.', './repo', 'owner/.')
 * - Leading or trailing dots ('.owner/repo', 'owner./repo', 'owner/.repo', 'owner/repo.')
 * - Whitespace (spaces, tabs, newlines)
 * - URL fragments ('#'), query parameters ('?'), schemes ('://'), ports (':')
 * - Backslashes ('\') and invalid separators ('//', multiple slashes)
 */
export function isValidCanonicalRepository(raw: string): boolean {
  if (typeof raw !== 'string') return false;

  // 1. Must not contain whitespace, URL fragments (#), query strings (?), protocol schemes or ports (:), or backslashes (\)
  if (/\s|[#\?:]|\\/.test(raw)) {
    return false;
  }

  // 2. Must contain exactly one '/' separator separating two non-empty segments
  const parts = raw.split('/');
  if (parts.length !== 2) {
    return false;
  }

  const [owner, repo] = parts;
  if (!owner || !repo) return false;

  // 3. Reject dot-only segments or segments containing consecutive dots (path traversal)
  if (owner === '.' || owner === '..' || repo === '.' || repo === '..') {
    return false;
  }
  if (owner.includes('..') || repo.includes('..')) {
    return false;
  }

  // 4. Reject leading or trailing dots on either segment
  if (owner.startsWith('.') || owner.endsWith('.') || repo.startsWith('.') || repo.endsWith('.')) {
    return false;
  }

  // 5. Each segment must consist of alphanumerics, hyphens, underscores, or single interior dots,
  // starting and ending with an alphanumeric character.
  const SEGMENT_REGEX = /^[a-zA-Z0-9](?:[a-zA-Z0-9_\-\.]*[a-zA-Z0-9])?$/;
  if (!SEGMENT_REGEX.test(owner) || !SEGMENT_REGEX.test(repo)) {
    return false;
  }

  return true;
}

/**
 * Normalizes a canonical repository identifier to lowercase after validation.
 */
export function normalizeCanonicalRepository(raw: string): string {
  if (!isValidCanonicalRepository(raw)) {
    throw new Error(
      `Invalid canonical repository format: '${raw}'. Expected 'owner/repo' without path traversal, dot segments, whitespace, or invalid characters.`
    );
  }
  return raw.trim().toLowerCase();
}

export const CanonicalRepositorySchema = z
  .string()
  .min(3, 'Repository identifier cannot be empty')
  .refine((val) => isValidCanonicalRepository(val), {
    message:
      "Repository identifier must be in canonical 'owner/repo' format without path traversal, dot segments, whitespace, or invalid characters"
  })
  .transform((val) => normalizeCanonicalRepository(val));

export const ResolutionVerificationStatusSchema = z.enum([
  'VERIFIED_RESOLVED',    // Merged PR, regression tests verified passing, confirmed resolution
  'PARTIAL_RESOLUTION',   // Partial mitigation or workaround
  'REGRESSED',            // Fix attempted but triggered regressions
  'UNVERIFIED_PROPOSAL'   // Staged or proposed without merged verification evidence
]);
export type ResolutionVerificationStatus = z.infer<typeof ResolutionVerificationStatusSchema>;

export const ResolutionHistoryEntrySchema = z.object({
  id: z.string().min(1),
  fromStatus: ResolutionVerificationStatusSchema.optional(),
  toStatus: ResolutionVerificationStatusSchema,
  timestamp: z.string().datetime({ message: 'Timestamp must be an ISO-8601 string' }),
  evidence: z.string().min(1, 'Evidence for status transition must be provided'),
  actor: z
    .object({
      type: z.enum(['HUMAN', 'SENTINEL', 'SYSTEM']),
      id: z.string().min(1),
      name: z.string().min(1)
    })
    .optional()
});
export type ResolutionHistoryEntry = z.infer<typeof ResolutionHistoryEntrySchema>;

export const IncidentMemoryRecordSchema = z.object({
  id: z.string().min(1, 'Incident ID cannot be empty'),
  canonicalRepository: CanonicalRepositorySchema,
  timestamp: z.string().datetime({ message: 'Timestamp must be an ISO-8601 string' }),
  category: IncidentCategorySchema,
  errorSignature: z.string().min(1, 'Error signature cannot be empty'),
  affectedTarget: z.string().min(1, 'Affected target file or module cannot be empty'),
  rootCause: z.string().min(1, 'Root cause description cannot be empty'),
  fixSummary: z.string().min(1, 'Fix summary cannot be empty'),
  diffHash: z.string().regex(/^[a-f0-9]{64}$/i, 'diffHash must be a 64-character SHA-256 hexadecimal string'),
  prLink: z.string().min(1, 'PR link or reference cannot be empty'),
  outcome: IncidentOutcomeSchema,
  verificationStatus: ResolutionVerificationStatusSchema,
  resolutionHistory: z.array(ResolutionHistoryEntrySchema).default([]),
  stackFrames: z.array(z.custom<ParsedStackFrame>()).optional(),
  metadata: z.record(z.unknown()).optional()
});
export type IncidentMemoryRecord = z.infer<typeof IncidentMemoryRecordSchema>;

export interface HistoricalMatchExplanation {
  overallScore: number;                // 0.0 to 1.0
  matchType: 'EXACT' | 'APPROXIMATE';
  similarityFactors: {
    signatureOverlapScore: number;     // Normalized signature token overlap (Weight 0.45)
    targetOverlapScore: number;        // Target component overlap (Weight 0.35)
    categoryOverlapScore: number;      // Category match (Weight 0.10)
    frameOverlapScore: number;         // Stack frame sequence overlap (Weight 0.10)
  };
  reasons: string[];                   // Traceable justifications
  distinguishingDifferences: string[]; // Documented divergences
}

export type ResolutionClassification =
  | 'VERIFIED_RESOLVED'
  | 'PARTIAL_RESOLUTION'
  | 'REGRESSED'
  | 'UNVERIFIED_PROPOSAL';

export interface HistoricalTransitionSummary {
  eventId: string;
  fromStatus?: ResolutionVerificationStatus | undefined;
  toStatus: ResolutionVerificationStatus;
  timestamp: string;
  actor?: {
    type: 'HUMAN' | 'SENTINEL' | 'SYSTEM';
    id: string;
    name: string;
  } | undefined;
  evidenceSummary: string;
  evidenceHash?: string | undefined;
  provenanceSource?: string | undefined;
  verificationType?: 'INDEPENDENTLY_VERIFIED' | 'USER_ASSERTION' | undefined;
  displayLabel?: string | undefined;
}

export interface HistoricalOutcomeReport {
  incidentId: string;
  canonicalRepository: string;
  currentStatus: ResolutionVerificationStatus;
  classification: ResolutionClassification;
  isRegressed: boolean;
  hasHistoricalRegression: boolean;
  doNotReuseAsProvenFix: boolean;
  recommendationAdvisory:
    | 'PROVEN_FIX_AVAILABLE'
    | 'PARTIAL_MITIGATION_ONLY'
    | 'REGRESSED_FIX_DO_NOT_REUSE'
    | 'UNVERIFIED_PROPOSAL_ONLY';
  rootCause: string;
  fixSummary: string;
  prLink: string;
  evidenceProvenanceSummary: {
    verificationType: 'INDEPENDENTLY_VERIFIED' | 'USER_ASSERTION' | 'MIXED' | 'NONE';
    displayLabel?: string | undefined;
    hasPassingRegressionTests: boolean;
    hasMergedPrEvidence: boolean;
    hasObservabilityProof: boolean;
    hasHumanConfirmation: boolean;
    missingOrUnavailableEvidence: string[];
  };
  chronologicalTransitions: HistoricalTransitionSummary[];
  rawHistoryCount: number;
}

export interface HistoricalIncidentMatch {
  record: IncidentMemoryRecord;
  similarity: HistoricalMatchExplanation;
  verificationStatus: ResolutionVerificationStatus;
  relevanceExplanation: string;
  outcomeReport: HistoricalOutcomeReport;
}

export const IncidentMemoryQuerySchema = z.object({
  canonicalRepository: CanonicalRepositorySchema,
  errorSignature: z.string().min(1, 'errorSignature query parameter cannot be empty'),
  category: IncidentCategorySchema.optional(),
  affectedTarget: z.string().optional(),
  stackFrames: z.array(z.custom<ParsedStackFrame>()).optional(),
  minSimilarityScore: z.number().min(0).max(1).default(0.60),
  maxResults: z.number().int().positive().default(5)
});
export type IncidentMemoryQuery = z.infer<typeof IncidentMemoryQuerySchema>;

export const QuarantinedRecordSchema = z.object({
  id: z.string().min(1),
  quarantinedAt: z.string().datetime({ message: 'quarantinedAt must be an ISO-8601 string' }),
  reason: z.string().min(1),
  // SHA-256 integrity fingerprint of the raw line content excluding line terminators (\r, \n)
  rawLineHash: z.string().regex(/^[a-f0-9]{64}$/i, 'rawLineHash must be a 64-character SHA-256 hex integrity fingerprint'),
  sanitizedContent: z.string()
});
export type QuarantinedRecord = z.infer<typeof QuarantinedRecordSchema>;

export interface IncidentStoreStats {
  totalRecords: number;
  repositories: Record<string, number>;
  quarantineCount: number;
}

