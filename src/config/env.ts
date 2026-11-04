import { z } from 'zod';

export const EnvSchema = z.object({
  SWITCH_CORE_URL: z
    .string()
    .url('SWITCH_CORE_URL must be a valid HTTP or HTTPS URL')
    .default('http://localhost:8080'),
  SWITCH_AGENT_ID: z
    .string()
    .min(1, 'SWITCH_AGENT_ID cannot be empty')
    .default('agn_devpulse_sentinel'),
  SWITCH_SENTINEL_AGENT_ID: z
    .string()
    .min(1, 'SWITCH_SENTINEL_AGENT_ID cannot be empty')
    .default('agn_devpulse_sentinel'),
  SWITCH_RUNNER_AGENT_ID: z
    .string()
    .min(1, 'SWITCH_RUNNER_AGENT_ID cannot be empty')
    .default('agn_devpulse_runner'),
  SWITCH_AGENT_API_KEY: z
    .string()
    .min(1, 'SWITCH_AGENT_API_KEY cannot be empty'),
  SWITCH_ROOM_ID: z
    .string()
    .min(1, 'SWITCH_ROOM_ID cannot be empty')
    .default('room_devpulse_ops'),
  MAINTAINER_ALLOWLIST: z
    .string()
    .transform((val) => val.split(',').map((id) => id.trim()).filter(Boolean))
    .refine((list) => list.length > 0, {
      message: 'MAINTAINER_ALLOWLIST must contain at least one authorized maintainer user ID'
    }),
  DEVPULSE_APPROVAL_SECRET: z
    .string()
    .min(32, 'DEVPULSE_APPROVAL_SECRET must be at least 32 characters long for cryptographic security'),
  AUDIT_LOG_PATH: z
    .string()
    .min(1)
    .default('./logs/audit.jsonl'),
  INCIDENT_STORE_PATH: z
    .string()
    .min(1)
    .default('./data/incidents.md'),
  INCIDENT_JSONL_PATH: z
    .string()
    .min(1)
    .default('./data/incidents.jsonl'),
  INCIDENT_QUARANTINE_PATH: z
    .string()
    .min(1)
    .default('./data/incidents.quarantine.jsonl'),
  CHALLENGE_STORE_PATH: z
    .string()
    .min(1)
    .default('./data/approval-challenges.jsonl'),
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development')
});

export type DevPulseConfig = z.infer<typeof EnvSchema>;

/**
 * Loads and validates configuration from environment variables or supplied overrides.
 */
export function loadConfig(overrides: Partial<Record<keyof DevPulseConfig, unknown>> = {}): DevPulseConfig {
  const envSource = {
    SWITCH_CORE_URL: overrides.SWITCH_CORE_URL ?? process.env['SWITCH_CORE_URL'],
    SWITCH_AGENT_ID: overrides.SWITCH_AGENT_ID ?? process.env['SWITCH_AGENT_ID'],
    SWITCH_SENTINEL_AGENT_ID: overrides.SWITCH_SENTINEL_AGENT_ID ?? process.env['SWITCH_SENTINEL_AGENT_ID'] ?? overrides.SWITCH_AGENT_ID ?? process.env['SWITCH_AGENT_ID'],
    SWITCH_RUNNER_AGENT_ID: overrides.SWITCH_RUNNER_AGENT_ID ?? process.env['SWITCH_RUNNER_AGENT_ID'],
    SWITCH_AGENT_API_KEY: overrides.SWITCH_AGENT_API_KEY ?? process.env['SWITCH_AGENT_API_KEY'],
    SWITCH_ROOM_ID: overrides.SWITCH_ROOM_ID ?? process.env['SWITCH_ROOM_ID'],
    MAINTAINER_ALLOWLIST: overrides.MAINTAINER_ALLOWLIST ?? process.env['MAINTAINER_ALLOWLIST'],
    DEVPULSE_APPROVAL_SECRET: overrides.DEVPULSE_APPROVAL_SECRET ?? process.env['DEVPULSE_APPROVAL_SECRET'],
    AUDIT_LOG_PATH: overrides.AUDIT_LOG_PATH ?? process.env['AUDIT_LOG_PATH'],
    INCIDENT_STORE_PATH: overrides.INCIDENT_STORE_PATH ?? process.env['INCIDENT_STORE_PATH'],
    INCIDENT_JSONL_PATH: overrides.INCIDENT_JSONL_PATH ?? process.env['INCIDENT_JSONL_PATH'],
    INCIDENT_QUARANTINE_PATH: overrides.INCIDENT_QUARANTINE_PATH ?? process.env['INCIDENT_QUARANTINE_PATH'],
    CHALLENGE_STORE_PATH: overrides.CHALLENGE_STORE_PATH ?? process.env['CHALLENGE_STORE_PATH'],
    NODE_ENV: overrides.NODE_ENV ?? process.env['NODE_ENV']
  };

  return EnvSchema.parse(envSource);
}
