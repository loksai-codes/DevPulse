import { promises as fs } from 'node:fs';
import * as path from 'node:path';

export interface EnvMap {
  [key: string]: string;
}

export function parseEnv(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx > 0) {
      const key = trimmed.slice(0, eqIdx).trim();
      let val = trimmed.slice(eqIdx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      result[key] = val;
    }
  }
  return result;
}

export function updateEnvString(existingContent: string, updates: Record<string, string>): string {
  const lines = existingContent.split(/\r?\n/);
  const updatedKeys = new Set<string>();

  const updatedLines = lines.map((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return line;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx > 0) {
      const key = trimmed.slice(0, eqIdx).trim();
      if (key in updates) {
        updatedKeys.add(key);
        return `${key}=${updates[key]}`;
      }
    }
    return line;
  });

  for (const [key, val] of Object.entries(updates)) {
    if (!updatedKeys.has(key)) {
      updatedLines.push(`${key}=${val}`);
    }
  }

  return updatedLines.join('\n');
}

export async function registerGateAgent(options?: {
  coreUrl?: string;
  registrationKey?: string;
  agentName?: string;
  envPath?: string;
  fetchFn?: typeof fetch;
}): Promise<{ success: boolean; agentId?: string; message: string }> {
  const fetchFn = options?.fetchFn ?? globalThis.fetch;
  const envFilePath = path.resolve(options?.envPath ?? './.env');

  let envVars: Record<string, string> = {};
  let rawEnvContent = '';
  try {
    rawEnvContent = await fs.readFile(envFilePath, 'utf8');
    envVars = parseEnv(rawEnvContent);
  } catch {
    // .env may not exist yet
  }

  const coreUrl = (options?.coreUrl ?? envVars['SWITCH_CORE_URL'] ?? process.env['SWITCH_CORE_URL'] ?? 'http://localhost:8080').replace(/\/+$/, '');
  const regKey = options?.registrationKey ?? envVars['SWITCH_REGISTRATION_KEY'] ?? process.env['SWITCH_REGISTRATION_KEY'];
  const agentName = options?.agentName ?? 'devpulse-gate';

  if (!regKey) {
    throw new Error(
      'SWITCH_REGISTRATION_KEY is not defined in .env or environment variables. ' +
      'Please obtain a registration-type API key from the Switch Gateway "API Keys" page.'
    );
  }

  // 1. Probe /health
  try {
    const healthRes = await fetchFn(`${coreUrl}/health`);
    if (!healthRes.ok && healthRes.status !== 401) {
      console.warn(`[WARN] Health check on ${coreUrl}/health returned HTTP ${healthRes.status}`);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[WARN] Health check on ${coreUrl}/health could not be reached: ${msg}`);
  }

  // 2. Register agent via POST /agents
  const registerPayload = {
    name: agentName,
    description: 'DevPulse Gate Agent: PR & Thread Governance with HITL verification',
    connector_type: 'custom-typescript',
    integration_profile: {
      connection_model: 'always_on',
      message_exchange: true,
      pre_invocation_mediation: [],
      post_invocation_mediation: [],
      event_reporting: []
    }
  };

  const regResponse = await fetchFn(`${coreUrl}/agents`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${regKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(registerPayload)
  });

  if (regResponse.status === 409) {
    return {
      success: false,
      message: `Agent '${agentName}' is already registered (HTTP 409). Using existing registration.`
    };
  }

  if (!regResponse.ok) {
    const errText = await regResponse.text().catch(() => '');
    throw new Error(`Registration failed [HTTP ${regResponse.status}]: ${errText || regResponse.statusText}`);
  }

  const regData = (await regResponse.json()) as { id?: string; agent_id?: string; api_key?: string };
  const agentId = regData.agent_id ?? regData.id;
  const apiKey = regData.api_key;

  if (!agentId || !apiKey) {
    throw new Error('Registration response did not return expected agent ID and API key.');
  }

  // 3. Set addressing to "anyone" so members can address the gate
  try {
    await fetchFn(`${coreUrl}/agents/${encodeURIComponent(agentId)}/ops/update_agent_detail`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        agent_id: agentId,
        addressing: 'anyone'
      })
    });
  } catch (err: unknown) {
    console.warn('[WARN] Could not update agent addressing detail:', err instanceof Error ? err.message : String(err));
  }

  // 4. Update .env file without printing secret
  const updatedEnv = updateEnvString(rawEnvContent, {
    SWITCH_AGENT_ID: agentId,
    SWITCH_GATE_AGENT_ID: agentId,
    SWITCH_AGENT_API_KEY: apiKey
  });

  await fs.writeFile(envFilePath, updatedEnv, 'utf8');

  return {
    success: true,
    agentId,
    message: `DevPulse Gate agent registered successfully as '${agentId}'. Credentials saved to .env.`
  };
}

// CLI entrypoint
if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}` || process.argv[1]?.endsWith('register.ts') || process.argv[1]?.endsWith('register.js')) {
  registerGateAgent()
    .then((result) => {
      console.log(`[SUCCESS] ${result.message}`);
      if (result.agentId) {
        console.log(`Agent ID: ${result.agentId}`);
      }
    })
    .catch((err) => {
      console.error(`[ERROR] Registration failed: ${err.message}`);
      process.exit(1);
    });
}
