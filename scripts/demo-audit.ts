/**
 * Runs one real DevPulse incident through the same components the e2e test
 * uses (Sentinel, memory, approval gate, Runner in a Docker sandbox), but
 * KEEPS the audit log so the dashboard has real data to show.
 *
 *   npm run demo:audit             (fast)
 *   npm run demo:audit -- --slow   (pauses between steps, for screen recording)
 *
 * Needs Docker Desktop running and the node:20-alpine image.
 * Output folder: logs/demo-run/ (git-ignored; wiped at the start of each run).
 *
 * Room messages are printed to this terminal instead of a Switch room, and the
 * people below are clearly labelled as simulated. In the live demo, a real
 * maintainer types the approval in the Switch room instead.
 */
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import { randomUUID } from 'node:crypto';

import { AuditLogger } from '../src/audit/audit-logger.js';
import { ChallengeTracker } from '../src/approval/challenge-tracker.js';
import { ApprovalHandler } from '../src/approval/approval-handler.js';
import { IncidentStore } from '../src/memory/incident-store.js';
import type { IncidentMemoryRecord } from '../src/memory/types.js';
import { SentinelAgent } from '../src/sentinel/sentinel-agent.js';
import { RunnerAgent } from '../src/patch-runner/runner-agent.js';
import { ContainerSandboxDriver } from '../src/patch-runner/sandbox-driver.js';
import { EventRouter } from '../src/router/event-router.js';
import { SwitchAdapter } from '../src/room/switch-adapter.js';
import type { NormalizedRoomEvent } from '../src/types/switch-protocol.js';

try {
  process.loadEnvFile('.env');
} catch {
  // No .env: fine.
}

const SLOW = process.argv.includes('--slow');
const pause = (ms: number) => (SLOW ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve());

const OUT_DIR = path.resolve('logs/demo-run');
const SAMPLE_REPO_PATH = path.resolve('tests/fixtures/sample-repo');
const ROOM_ID = 'room_devpulse_demo';
const SENTINEL_ID = 'agt_sentinel_demo';
const RUNNER_ID = 'agt_runner_demo';
const MAINTAINER_ID = 'usr_demo_maintainer';
const OUTSIDER_ID = 'usr_demo_outsider';
const secretKey = process.env.DEVPULSE_AUDIT_SECRET ?? process.env.DEVPULSE_APPROVAL_SECRET;

function roomEvent(overrides: Partial<NormalizedRoomEvent>): NormalizedRoomEvent {
  return {
    eventId: `evt_${randomUUID().slice(0, 8)}`,
    roomId: ROOM_ID,
    senderId: MAINTAINER_ID,
    senderName: 'Simulated maintainer',
    senderType: 'USER',
    body: '',
    isNativeConsole: true,
    bridgeId: null,
    addressedToMe: true,
    isSelfMessage: false,
    timestamp: Date.now(),
    raw: {},
    ...overrides
  } as NormalizedRoomEvent;
}

function step(title: string): void {
  console.log(`\n=== ${title} ===`);
}

async function main(): Promise<void> {
  await fs.rm(OUT_DIR, { recursive: true, force: true });
  await fs.mkdir(OUT_DIR, { recursive: true });

  const auditFile = path.join(OUT_DIR, 'audit.jsonl');
  const auditLogger = new AuditLogger(secretKey ? { filePath: auditFile, secretKey } : { filePath: auditFile });
  await auditLogger.init();

  const challengeTracker = new ChallengeTracker({ persistenceFilePath: path.join(OUT_DIR, 'challenges.jsonl') });
  await challengeTracker.init();

  const incidentStore = new IncidentStore({
    jsonlPath: path.join(OUT_DIR, 'incidents.jsonl'),
    markdownPath: path.join(OUT_DIR, 'incidents.md'),
    quarantinePath: path.join(OUT_DIR, 'quarantine.jsonl')
  });
  await incidentStore.init();

  // One earlier incident in memory, so Sentinel's recall is visible.
  const pastIncident: IncidentMemoryRecord = {
    id: 'INC-2026-PAST01',
    canonicalRepository: 'devpulse/core',
    timestamp: '2026-11-04T10:00:00.000Z',
    category: 'RUNTIME_EXCEPTION',
    affectedTarget: 'src/auth.js',
    errorSignature: "TypeError: Cannot read properties of null (reading 'expiresAt')",
    rootCause: 'Null dereference in session token object',
    fixSummary: 'Guard token dereference with optional chaining and fallback',
    diffHash: 'a'.repeat(64),
    prLink: 'https://github.com/devpulse/core/pull/88',
    outcome: 'RESOLVED',
    verificationStatus: 'VERIFIED_RESOLVED',
    resolutionHistory: []
  };
  await incidentStore.append(pastIncident);

  const sandboxDriver = new ContainerSandboxDriver({
    runtimeBinary: 'docker',
    defaultImage: 'node:20-alpine',
    defaultTimeoutMs: 30000
  });

  const sentinel = new SentinelAgent({
    agentId: SENTINEL_ID,
    runnerAgentId: RUNNER_ID,
    maintainerAllowlist: [MAINTAINER_ID],
    challengeTracker,
    auditLogger,
    incidentStore,
    defaultCanonicalRepository: 'devpulse/core'
  });

  const runner = new RunnerAgent({
    agentId: RUNNER_ID,
    sentinelAgentId: SENTINEL_ID,
    challengeTracker,
    auditLogger,
    sandboxDriver,
    sampleRepoTemplatePath: SAMPLE_REPO_PATH,
    sandboxImage: 'node:20-alpine'
  });

  const approvalHandler = new ApprovalHandler({ maintainerAllowlist: [MAINTAINER_ID], challengeTracker, auditLogger });

  // Local adapter: room messages go to this terminal, not to a Switch server.
  const adapter = new SwitchAdapter({
    coreUrl: 'http://127.0.0.1:0',
    agentId: SENTINEL_ID,
    apiKey: 'local-demo-not-a-real-key',
    roomId: ROOM_ID
  });
  const roomMessages: string[] = [];
  adapter.sendMessage = async (body: string) => {
    roomMessages.push(body);
    console.log(`\n[room message]\n${body}\n`);
    return { success: true, messageId: `msg_${randomUUID()}` };
  };

  const router = new EventRouter({
    adapter,
    sentinel,
    runner,
    approvalHandler,
    auditLogger,
    canonicalRepository: 'devpulse/core'
  });

  step('1. Alert arrives in the room');
  const investigation = await router.routeEvent(
    roomEvent({
      senderId: 'usr_demo_alert_bridge',
      senderName: 'Simulated alert bridge',
      body: [
        "incident: TypeError: Cannot read properties of null (reading 'expiresAt')",
        '    at getSessionExpiration (src/auth.js:24:12)',
        '    at handleRequest (src/server.js:88:9)'
      ].join('\n')
    })
  );
  console.log(`Router result: ${investigation.action}`);
  await pause(3000);

  const challengeId = roomMessages.join('\n').match(/appr_[a-f0-9]+/)?.[0];
  if (!challengeId) {
    throw new Error('Sentinel did not post an approval challenge. Check the room message above.');
  }

  step('2. Security check: a user who is not a maintainer tries to approve');
  const rejected = await router.routeEvent(
    roomEvent({ senderId: OUTSIDER_ID, senderName: 'Simulated outsider', body: `@devpulse approve ${challengeId}` })
  );
  console.log(`Router result: ${rejected.action}`);
  await pause(3000);

  step('3. The maintainer approves');
  const executed = await router.routeEvent(roomEvent({ body: `@devpulse approve ${challengeId}` }));
  console.log(`Router result: ${executed.action}`);
  await pause(1000);

  step('4. Audit chain check');
  const integrity = await auditLogger.verifyChainIntegrity();
  console.log(integrity.valid ? 'Audit chain intact.' : `Audit chain broken: ${integrity.reason}`);

  console.log(`\nAudit log written to ${path.relative(process.cwd(), auditFile)}`);
  console.log('See it in the dashboard: npm run dashboard -- --file=logs/demo-run/audit.jsonl');
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
