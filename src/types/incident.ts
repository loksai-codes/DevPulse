import { z } from 'zod';

export const IncidentOutcomeSchema = z.enum([
  'RESOLVED',
  'REGRESSED',
  'PARTIAL',
  'CLOSED_WITHOUT_MERGE'
]);

export type IncidentOutcome = z.infer<typeof IncidentOutcomeSchema>;

export const IncidentRecordSchema = z.object({
  id: z.string().min(1, 'Incident ID cannot be empty'),
  timestamp: z.string().datetime({ message: 'Timestamp must be an ISO-8601 string' }),
  errorSignature: z.string().min(1, 'Error signature cannot be empty'),
  affectedTarget: z.string().min(1, 'Affected target file or module cannot be empty'),
  rootCause: z.string().min(1, 'Root cause description cannot be empty'),
  fixSummary: z.string().min(1, 'Fix summary cannot be empty'),
  diffHash: z.string().regex(/^[a-f0-9]{64}$/i, 'diffHash must be a 64-character SHA-256 hexadecimal string'),
  prLink: z.string().min(1, 'PR link or reference cannot be empty'),
  outcome: IncidentOutcomeSchema,
  metadata: z.record(z.unknown()).optional()
});

export type IncidentRecord = z.infer<typeof IncidentRecordSchema>;

