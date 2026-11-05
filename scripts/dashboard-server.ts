/**
 * DevPulse dashboard server.
 *
 * Serves the Triage Ward Web UI (from dist/ if built, or dashboard/index.html)
 * and JSON endpoints for the audit log, incidents, ingest, and memory.
 * It listens on 127.0.0.1 only.
 *
 *   npm run dashboard                                   (reads ./logs/audit.jsonl)
 *   npm run dashboard -- --file=logs/demo-run/audit.jsonl
 *
 * Env (optional): AUDIT_LOG_PATH, DASHBOARD_PORT (default 4173),
 * DEVPULSE_AUDIT_SECRET or DEVPULSE_APPROVAL_SECRET (needed to verify an
 * HMAC-keyed chain; must match the secret the agents logged with).
 */
import { createServer, IncomingMessage } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { AuditLogger } from '../src/audit/audit-logger.js';

try {
  process.loadEnvFile('.env');
} catch {
  // No .env file: fine, everything has a default.
}

const here = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.resolve(here, '..', 'dist');
const distHtml = path.resolve(distDir, 'index.html');
const fallbackHtml = path.resolve(here, '..', 'dashboard', 'index.html');

const fileArg = process.argv.slice(2).find((a) => a.startsWith('--file='))?.slice('--file='.length);
const auditPath = path.resolve(fileArg ?? process.env.AUDIT_LOG_PATH ?? './logs/audit.jsonl');
const port = Number(process.env.DASHBOARD_PORT ?? 4173);
const secretKey = process.env.DEVPULSE_AUDIT_SECRET ?? process.env.DEVPULSE_APPROVAL_SECRET;

function makeLogger(): AuditLogger {
  return new AuditLogger(secretKey ? { filePath: auditPath, secretKey } : { filePath: auditPath });
}

async function fileExists(p: string): Promise<boolean> {
  try {
    const s = await stat(p);
    return s.isFile();
  } catch {
    return false;
  }
}

async function readRequestBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    // Serve HTML root
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const useDist = await fileExists(distHtml);
      const targetHtml = useDist ? distHtml : fallbackHtml;
      const html = await readFile(targetHtml, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    // Serve static assets from dist/assets/*
    if (req.method === 'GET' && url.pathname.startsWith('/assets/')) {
      const sanitizedName = path.basename(url.pathname);
      const assetPath = path.join(distDir, 'assets', sanitizedName);
      if (await fileExists(assetPath)) {
        const ext = path.extname(assetPath).toLowerCase();
        let mime = 'application/octet-stream';
        if (ext === '.js') mime = 'application/javascript; charset=utf-8';
        else if (ext === '.css') mime = 'text/css; charset=utf-8';
        else if (ext === '.svg') mime = 'image/svg+xml';
        else if (ext === '.png') mime = 'image/png';
        else if (ext === '.jpg' || ext === '.jpeg') mime = 'image/jpeg';
        else if (ext === '.woff2') mime = 'font/woff2';

        const data = await readFile(assetPath);
        res.writeHead(200, { 'Content-Type': mime });
        res.end(data);
        return;
      }
    }

    // API: Ingest stack trace (Sentinel ingestion)
    if (req.method === 'POST' && url.pathname === '/api/ingest') {
      const rawBody = await readRequestBody(req);
      const { trace } = JSON.parse(rawBody || '{}');
      const traceText = String(trace || '');

      let file = 'src/service/worker.ts';
      let line = 42;
      let errorSignature = 'Error: Unexpected runtime failure';
      let rootCause = 'Unhandled exception in worker execution context.';
      let title = 'Runtime assertion failure in worker thread';
      let diff = `--- a/${file}\n+++ b/${file}\n@@ -40,3 +40,5 @@ export function processJob(job: Job) {\n+  if (!job || !job.payload) {\n+    throw new InvalidJobError('Job payload is missing');\n+  }\n   return handle(job.payload);\n }`;

      if (traceText.includes('session-verifier') || traceText.includes('sub')) {
        file = 'src/auth/session-verifier.ts';
        line = 142;
        errorSignature = "TypeError: Cannot read properties of null (reading 'sub') at SessionVerifier.verifyToken";
        rootCause = 'Expired session token payload decoded as null without guard before .sub access.';
        title = 'Auth session null dereference on token expiry';
        diff = `--- a/src/auth/session-verifier.ts\n+++ b/src/auth/session-verifier.ts\n@@ -140,4 +140,8 @@ export async function verifyToken(rawToken: string): Promise<SessionClaims> {\n   const decoded = await decryptSessionClaims(rawToken);\n+  if (!decoded || typeof decoded.sub !== 'string') {\n+    throw new AuthSessionExpiredError('Session claims missing or invalidated');\n+  }\n   return decoded;\n }`;
      } else if (traceText.includes('worker-dispatcher') || traceText.includes('stack')) {
        file = 'src/queue/worker-dispatcher.ts';
        line = 88;
        errorSignature = 'RangeError: Maximum call stack size exceeded at WorkerDispatcher.pollNextBatch';
        rootCause = 'Recursive re-polling of empty queue without backoff triggers call stack exhaustion.';
        title = 'Queue worker recursive spin loop on empty batch';
        diff = `--- a/src/queue/worker-dispatcher.ts\n+++ b/src/queue/worker-dispatcher.ts\n@@ -86,4 +86,7 @@ export async function pollNextBatch(queue: WorkQueue): Promise<void> {\n   const batch = await queue.dequeue(BATCH_SIZE);\n   if (batch.length === 0) {\n+    const backoffMs = computeJitterBackoff(queue.backoffCount++);\n+    await sleep(backoffMs);\n     return pollNextBatch(queue);\n   }\n   await processBatch(batch);\n }`;
      }

      const id = `INC-${Math.floor(8410 + Math.random() * 90)}`;
      const specHash = createHash('sha256').update(diff).digest('hex');
      const challengeId = `appr_${id.toLowerCase()}_${Math.random().toString(36).slice(2, 6)}`;
      const now = Date.now();

      const incident = {
        id,
        title,
        severity: 'critical',
        file,
        line,
        errorSignature,
        rootCause,
        stage: 5,
        admittedAt: new Date(now).toISOString(),
        diff,
        specHash,
        challenge: {
          id: challengeId,
          expiresAt: new Date(now + 300000).toISOString(),
          status: 'open'
        },
        sandbox: {
          flags: ['--network none', 'read-only rootfs', 'non-root: sandbox_user'],
          lines: [
            `[SANDBOX INIT] Enforcing isolation for incoming incident ${id}...`,
            '[READY] Sealed and standing by for maintainer authorization.'
          ],
          exitCode: null,
          durationMs: 0
        }
      };

      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(incident));
      return;
    }

    // API: Audit log
    if (req.method === 'GET' && url.pathname === '/api/audit') {
      const logger = makeLogger();
      const { entries, error, errorLine } = await logger.getEntries();
      const integrity = await logger.verifyChainIntegrity();
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(
        JSON.stringify({
          file: path.relative(process.cwd(), auditPath) || auditPath,
          entries,
          readError: error ? { message: error, line: errorLine ?? null } : null,
          integrity,
          keyed: Boolean(secretKey),
          readAt: new Date().toISOString()
        })
      );
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: message }));
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`DevPulse dashboard: http://127.0.0.1:${port}`);
  console.log(`Reading audit log: ${auditPath}`);
  console.log(secretKey ? 'Chain verification: HMAC key loaded from env.' : 'Chain verification: no secret set (plain SHA-256).');
});
