import { z } from 'zod';

export const RiskLevelSchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

export const RiskReportSchema = z.object({
  riskScore: z
    .number()
    .int('Risk score must be an integer')
    .min(0, 'Risk score cannot be below 0')
    .max(100, 'Risk score cannot exceed 100'),
  riskLevel: RiskLevelSchema,
  blastRadius: z.array(z.string().min(1)).min(1, 'At least one affected file or module must be specified'),
  testsImpacted: z.array(z.string().min(1)),
  rollbackStrategy: z.string().min(1, 'Rollback strategy must be explicitly documented'),
  complianceNotes: z.string().optional(),
  safetyGuarantees: z.array(z.string().min(1))
});

export type RiskReport = z.infer<typeof RiskReportSchema>;

/**
 * Utility to compute recommended RiskLevel based on the score.
 */
export function calculateRiskLevel(score: number): RiskLevel {
  if (score < 25) return 'LOW';
  if (score < 55) return 'MEDIUM';
  if (score < 80) return 'HIGH';
  return 'CRITICAL';
}

