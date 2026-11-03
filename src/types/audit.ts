import { z } from 'zod';

export const AuditActorTypeSchema = z.enum(['SENTINEL', 'PATCH_RUNNER', 'HUMAN', 'SYSTEM']);
export type AuditActorType = z.infer<typeof AuditActorTypeSchema>;

export const AuditActorSchema = z.object({
  type: AuditActorTypeSchema,
  id: z.string().min(1),
  name: z.string().min(1)
});
export type AuditActor = z.infer<typeof AuditActorSchema>;

export const AuditLogEntrySchema = z.object({
  id: z.string().min(1, 'Audit log ID is required'),
  timestamp: z.string().datetime({ message: 'Timestamp must be an ISO-8601 string' }),
  sequence: z.number().int().nonnegative('Sequence must be a non-negative monotonic integer'),
  actor: AuditActorSchema,
  action: z.string().min(1, 'Action description is required'),
  incidentId: z.string().optional(),
  specId: z.string().optional(),
  payload: z.record(z.unknown()),
  prevHash: z.string().regex(/^[a-f0-9]{64}$/i, 'prevHash must be a 64-character SHA-256 string'),
  hash: z.string().regex(/^[a-f0-9]{64}$/i, 'hash must be a 64-character SHA-256 string')
});

export type AuditLogEntry = z.infer<typeof AuditLogEntrySchema>;

