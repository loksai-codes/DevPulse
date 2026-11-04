import http from 'node:http';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { SwitchAdapter } from '../room/switch-adapter.js';
import { NormalizedRoomEvent } from '../types/switch-protocol.js';
import { parseEnv } from './register.js';

export interface GateServerOptions {
  coreUrl?: string;
  agentId?: string;
  apiKey?: string;
  roomId?: string;
  maintainers?: string[];
  alertPort?: number;
  adapter?: SwitchAdapter;
}

export class DevPulseGateServer {
  public readonly coreUrl: string;
  public readonly agentId: string;
  public readonly apiKey: string;
  public readonly roomId: string;
  public readonly maintainers: string[];
  public readonly alertPort: number;

  private adapter: SwitchAdapter;
  private httpServer?: http.Server;

  constructor(options: GateServerOptions) {
    this.coreUrl = (options.coreUrl ?? process.env['SWITCH_CORE_URL'] ?? 'http://localhost:8080').replace(/\/+$/, '');
    this.agentId = options.agentId ?? process.env['SWITCH_AGENT_ID'] ?? process.env['SWITCH_GATE_AGENT_ID'] ?? 'agn_devpulse_gate';
    this.apiKey = options.apiKey ?? process.env['SWITCH_AGENT_API_KEY'] ?? '';
    this.roomId = options.roomId ?? process.env['SWITCH_ROOM_ID'] ?? 'devpulse-ops';
    this.alertPort = options.alertPort ?? parseInt(process.env['ALERT_PORT'] ?? '3030', 10);

    const allowlistRaw = process.env['MAINTAINER_ALLOWLIST'] ?? '';
    this.maintainers = options.maintainers ?? allowlistRaw.split(',').map((s) => s.trim()).filter(Boolean);

    this.adapter = options.adapter ?? new SwitchAdapter({
      coreUrl: this.coreUrl,
      agentId: this.agentId,
      apiKey: this.apiKey,
      roomId: this.roomId
    });

    this.setupListeners();
  }

  private setupListeners(): void {
    this.adapter.on('open', async () => {
      console.log(`[DevPulse Gate] Connected to Switch Core WebSocket at ${this.coreUrl}`);
      try {
        await this.adapter.sendMessage('DevPulse Gate online');
        console.log(`[DevPulse Gate] Posted "DevPulse Gate online" to room '${this.roomId}'`);
      } catch (err: unknown) {
        console.error('[DevPulse Gate] Failed to post online greeting:', err instanceof Error ? err.message : String(err));
      }
    });

    this.adapter.on('message', async (event: NormalizedRoomEvent) => {
      await this.handleRoomMessage(event);
    });

    this.adapter.on('error', (err) => {
      console.error('[DevPulse Gate] WebSocket error:', err instanceof Error ? err.message : String(err));
    });
  }

  public async handleRoomMessage(event: NormalizedRoomEvent): Promise<void> {
    // 1. Only process messages explicitly addressed to this gate or mentioning @devpulse-gate
    const body = event.body.trim();
    const isDirectlyAddressed = event.addressedToMe || body.startsWith('@devpulse-gate');
    if (!isDirectlyAddressed) return;

    // 2. Reject bridged chat origins (Slack/Discord/Teams) - HITL approvals must be in native Switch room
    if (!event.isNativeConsole || event.bridgeId !== null) {
      await this.adapter.sendMessage(
        `⛔ **[APPROVAL FORBIDDEN]** Approvals must originate natively from the Switch Console room, not from external bridged chat (${event.bridgeId ?? 'external'}).`,
        event.threadId
      );
      return;
    }

    // 3. Human sender check
    if (event.senderType !== 'USER') {
      await this.adapter.sendMessage(
        `⛔ **[APPROVAL FORBIDDEN]** Autonomous agents or bots cannot authorize production changes.`,
        event.threadId
      );
      return;
    }

    // 4. Maintainer allowlist check
    if (this.maintainers.length > 0 && !this.maintainers.includes(event.senderId)) {
      await this.adapter.sendMessage(
        `⛔ **[APPROVAL FORBIDDEN]** User '${event.senderName}' (${event.senderId}) is not in the MAINTAINER_ALLOWLIST.`,
        event.threadId
      );
      return;
    }

    // 5. Check for approve / reject command syntax
    const approveMatch = body.match(/^@devpulse-gate\s+approve\s+(\S+)\s+([a-f0-9]{12,64})/i);
    const rejectMatch = body.match(/^@devpulse-gate\s+reject\s+(\S+)\s+(.+)/i);

    if (approveMatch) {
      const incidentId = approveMatch[1];
      const diffPrefix = approveMatch[2];
      await this.adapter.sendMessage(
        `⏳ **[APPROVAL PROCESSING]** Validating approval for \`${incidentId}\` with diff signature \`${diffPrefix}\`...`,
        event.threadId
      );
      // M4 will complete the full git push + gh pr create workflow
      return;
    }

    if (rejectMatch) {
      const incidentId = rejectMatch[1];
      const reason = rejectMatch[2];
      await this.adapter.sendMessage(
        `🛑 **[INCIDENT REJECTED]** Incident \`${incidentId}\` rejected by ${event.senderName}. Reason: ${reason}`,
        event.threadId
      );
      return;
    }
  }

  public async startHttpAlertListener(): Promise<void> {
    return new Promise((resolve) => {
      this.httpServer = http.createServer(async (req, res) => {
        if (req.method === 'POST' && req.url === '/alert') {
          let body = '';
          req.on('data', (chunk) => { body += chunk; });
          req.on('end', async () => {
            try {
              const parsed = JSON.parse(body || '{}');
              const alertSummary = parsed.message || parsed.error || parsed.summary || 'Unspecified alert received';
              const alertDetails = parsed.service ? ` (Service: ${parsed.service})` : '';

              const roomMessage = `🚨 **[ALERT]** ${alertSummary}${alertDetails} @sentinel please investigate.`;
              await this.adapter.sendMessage(roomMessage);

              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: true, message: 'Alert posted to room', alert: alertSummary }));
            } catch (err: unknown) {
              const message = err instanceof Error ? err.message : String(err);
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: false, error: message }));
            }
          });
        } else if (req.method === 'GET' && req.url === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', service: 'devpulse-gate' }));
        } else {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not Found');
        }
      });

      this.httpServer.listen(this.alertPort, () => {
        console.log(`[DevPulse Gate] HTTP alert listener running at http://localhost:${this.alertPort}/alert`);
        resolve();
      });
    });
  }

  public async start(): Promise<void> {
    await this.startHttpAlertListener();
    await this.adapter.connect();
  }

  public async stop(): Promise<void> {
    if (this.httpServer) {
      await new Promise<void>((resolve) => this.httpServer!.close(() => resolve()));
    }
    await this.adapter.disconnect();
  }
}

// Standalone entrypoint
async function main() {
  // Load .env if present
  try {
    const envPath = path.resolve('./.env');
    const content = await fs.readFile(envPath, 'utf8');
    const parsed = parseEnv(content);
    for (const [k, v] of Object.entries(parsed)) {
      if (!process.env[k]) {
        process.env[k] = v;
      }
    }
  } catch {}

  const server = new DevPulseGateServer({});
  await server.start();
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}` || process.argv[1]?.endsWith('gate.ts') || process.argv[1]?.endsWith('gate/index.ts')) {
  main().catch((err) => {
    console.error('[FATAL] Gate server failed to start:', err);
    process.exit(1);
  });
}
