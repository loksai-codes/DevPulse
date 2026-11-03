import { z } from 'zod';
import { RiskReportSchema } from './risk-report.js';

export const PatchActionSchema = z.enum(['MODIFY', 'CREATE', 'DELETE']);
export type PatchAction = z.infer<typeof PatchActionSchema>;

export const FilePatchSchema = z.object({
  path: z
    .string()
    .min(1, 'File path is required')
    .refine((p) => !p.includes('..'), {
      message: 'Path traversal (..) is not permitted in patch paths'
    })
    .refine((p) => !p.startsWith('/') && !p.startsWith('\\'), {
      message: 'Patch paths must be relative to repository root'
    }),
  action: PatchActionSchema,
  patchDiff: z
    .string()
    .min(1, 'Unified patch diff cannot be empty')
    .refine((d) => d.trim().length > 0, {
      message: 'Patch diff cannot be purely whitespace'
    })
});
export type FilePatch = z.infer<typeof FilePatchSchema>;

export const RemediationStatusSchema = z.enum([
  'PROPOSED',
  'PREPARED_IN_WORKTREE',
  'TESTS_PASSED',
  'TESTS_FAILED',
  'PENDING_HUMAN_APPROVAL',
  'APPROVED',
  'REJECTED',
  'PR_OPENED'
]);
export type RemediationStatus = z.infer<typeof RemediationStatusSchema>;

export const TestRunResultSchema = z.object({
  command: z.string().min(1),
  exitCode: z.number().int(),
  passed: z.boolean(),
  output: z.string(),
  durationMs: z.number().nonnegative(),
  executedAt: z.string().datetime()
});
export type TestRunResult = z.infer<typeof TestRunResultSchema>;

export const RemediationSpecSchema = z.object({
  id: z.string().min(1, 'Spec ID is required'),
  incidentId: z.string().min(1, 'Incident ID is required'),
  createdAt: z.string().datetime({ message: 'createdAt must be an ISO-8601 string' }),
  targetRepository: z.string().min(1, 'Target repository cannot be empty'),
  baseBranch: z.string().min(1, 'Base branch cannot be empty'),
  targetBranch: z.string().min(1, 'Target branch cannot be empty'),
  errorSignature: z.string().min(1, 'Error signature cannot be empty'),
  rootCause: z.string().min(1, 'Root cause cannot be empty'),
  patches: z.array(FilePatchSchema).min(1, 'At least one file patch must be provided'),
  diffHash: z.string().regex(/^[a-f0-9]{64}$/i, 'diffHash must be a 64-character SHA-256 hexadecimal string'),
  riskReport: RiskReportSchema,
  verificationCommands: z.array(z.string().min(1)).min(1, 'At least one verification command is required'),
  status: RemediationStatusSchema,
  testRunResults: z.array(TestRunResultSchema).optional(),
  metadata: z.record(z.unknown()).optional()
});

export type RemediationSpec = z.infer<typeof RemediationSpecSchema>;
