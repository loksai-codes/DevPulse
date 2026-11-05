/**
 * DevPulse dashboard server (read-only).
 *
 * Serves dashboard/index.html and a JSON view of the audit log, using the
 * project's own AuditLogger to read entries and verify the hash chain.
 * It never writes to the log. It listens on 127.0.0.1 only.
 *
 *   npm run dashboard                                   (reads ./logs/audit.jsonl)
 *   npm run dashboard -- --file=logs/demo-run/audit.jsonl
 *
 * Env (optional): AUDIT_LOG_PATH, DASHBOARD_PORT (default 4173),
 * DEVPULSE_AUDIT_SECRET or DEVPULSE_APPROVAL_SECRET (needed to verify an
 * HMAC-keyed chain; must match the secret the agents logged with).
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuditLogger } from '../src/audit/audit-logger.js';

try {
  process.loadEnvFile('.env');
} catch {
  // No .env file: fine, everything has a default.
}

const here = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.resolve(here, '..', 'dashboard', 'index.html');

const fileArg = process.argv.slice(2).find((a) => a.startsWith('--file='))?.slice('--file='.length);
const auditPath = path.resolve(fileArg ?? process.env.AUDIT_LOG_PATH ?? './logs/audit.jsonl');
const port = Number(process.env.DASHBOARD_PORT ?? 4173);
const secretKey = process.env.DEVPULSE_AUDIT_SECRET ?? process.env.DEVPULSE_APPROVAL_SECRET;

function makeLogger(): AuditLogger {
  return new AuditLogger(secretKey ? { filePath: auditPath, secretKey } : { filePath: auditPath });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  try {
    if (req.method === 'GET' && url.pathname === '/') {
      const html = await readFile(htmlPath, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

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
