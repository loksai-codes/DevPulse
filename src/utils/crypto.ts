import { createHash, createHmac } from 'node:crypto';
import { promises as fs, appendFileSync, unlinkSync, mkdirSync } from 'node:fs';
import * as path from 'node:path';
import type { FilePatch } from '../types/remediation.js';
import type { HumanApproval } from '../types/human-approval.js';
import type { RemediationSpec } from '../types/remediation.js';
import type { AuditLogEntry } from '../types/audit.js';

export const GENESIS_HASH = '0'.repeat(64);
const DEFAULT_MAX_APPROVAL_AGE_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Retrieves the approval HMAC secret from environment.
 * Requires at least 32 characters in production.
 */
export function getApprovalSecret(explicitKey?: string): string {
  const key = explicitKey ?? process.env['DEVPULSE_APPROVAL_SECRET'];
  if (!key) {
    if (process.env['NODE_ENV'] === 'test') {
      return 'test-secret-devpulse-32-chars-long-min-required';
    }
    throw new Error(
      'DEVPULSE_APPROVAL_SECRET environment variable is missing. Refusing to run with insecure default secret.'
    );
  }
  if (key.length < 32) {
    throw new Error('DEVPULSE_APPROVAL_SECRET must be at least 32 characters long for cryptographic security.');
  }
  return key;
}

/**
 * Normalizes string line endings to LF and trims outer whitespace.
 */
export function normalizeText(text: string): string {
  return text.replace(/\r\n/g, '\n').trim();
}

/**
 * Computes a deterministic SHA-256 hash for patch diffs.
 * Uses length-prefixed encoding to prevent boundary/delimiter injection attacks.
 */
export function computeDiffHash(input: string | FilePatch[]): string {
  const hash = createHash('sha256');

  if (typeof input === 'string') {
    const normalized = normalizeText(input);
    hash.update(`raw:${normalized.length}:${normalized}`, 'utf8');
  } else {
    const sorted = [...input].sort((a, b) => a.path.localeCompare(b.path));
    hash.update(`count:${sorted.length}\n`);
    for (const patch of sorted) {
      const normalizedPath = patch.path.trim();
      const normalizedDiff = normalizeText(patch.patchDiff);
      // Length-prefixed encoding: type:len:content
      hash.update(
        `p:${normalizedPath.length}:${normalizedPath}|a:${patch.action}|d:${normalizedDiff.length}:${normalizedDiff}\n`,
        'utf8'
      );
    }
  }

  return hash.digest('hex');
}

/**
 * Computes a cryptographic hash binding the complete remediation specification:
 * diffHash + targetRepository + baseBranch + targetBranch + verificationCommands + incidentId.
 * This ensures parameters cannot be tampered with even if the diff remains unchanged.
 */
export function computeSpecHash(
  spec: Pick<RemediationSpec, 'id' | 'incidentId' | 'targetRepository' | 'baseBranch' | 'targetBranch' | 'diffHash' | 'verificationCommands'>
): string {
  const hash = createHash('sha256');
  const sortedCommands = [...spec.verificationCommands].sort();
  const serialized = [
    spec.id,
    spec.incidentId,
    spec.targetRepository,
    spec.baseBranch,
    spec.targetBranch,
    spec.diffHash,
    sortedCommands.join(';')
  ].join('|');
  hash.update(serialized, 'utf8');
  return hash.digest('hex');
}

/**
 * Generates an HMAC-SHA256 signature binding the human approval to:
 * - unique approvalId (UUID)
 * - specId
 * - diffHash
 * - specHash (optional but recommended for parameter integrity)
 * - userId
 * - approvedAt
 * - nonce
 */
export function computeApprovalSignature(
  approvalId: string,
  specId: string,
  diffHash: string,
  userId: string,
  approvedAt: string,
  nonce: string,
  secretKey?: string,
  specHash?: string
): string {
  const secret = getApprovalSecret(secretKey);
  const payload = [
    approvalId,
    specId,
    diffHash,
    specHash ?? '',
    userId,
    approvedAt,
    nonce
  ].join('|');
  return createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
}

/**
 * Thread-safe and persistent nonce tracker to guarantee that approvals cannot be replayed.
 * Features atomic consume() to prevent TOCTOU concurrency race conditions.
 */
export class ApprovalNonceTracker {
  private consumedApprovals = new Set<string>();
  private persistenceFilePath?: string;

  constructor(persistenceFilePath?: string) {
    if (persistenceFilePath) {
      this.persistenceFilePath = path.resolve(persistenceFilePath);
    }
  }

  public async init(): Promise<void> {
    if (!this.persistenceFilePath) return;
    try {
      await fs.mkdir(path.dirname(this.persistenceFilePath), { recursive: true });
      const content = await fs.readFile(this.persistenceFilePath, 'utf8');
      const lines = content.trim().split('\n').filter(Boolean);
      for (const line of lines) {
        this.consumedApprovals.add(line.trim());
      }
    } catch (err: unknown) {
      const error = err as NodeJS.ErrnoException;
      if (error.code !== 'ENOENT') throw error;
    }
  }

  /**
   * Atomically checks if the approval was already consumed. If not, records it.
   * Returns true if successfully consumed (was NOT replayed), false if replayed.
   */
  public consume(approvalId: string, nonce: string): boolean {
    const key = `${approvalId}:${nonce}`;
    if (this.consumedApprovals.has(key)) {
      return false; // Already consumed! Replay attack.
    }
    this.consumedApprovals.add(key);

    if (this.persistenceFilePath) {
      mkdirSync(path.dirname(this.persistenceFilePath), { recursive: true });
      appendFileSync(this.persistenceFilePath, key + '\n', 'utf8');
    }
    return true;
  }

  public isConsumed(approvalId: string, nonce: string): boolean {
    return this.consumedApprovals.has(`${approvalId}:${nonce}`);
  }

  public clear(): void {
    this.consumedApprovals.clear();
    if (this.persistenceFilePath) {
      try {
        unlinkSync(this.persistenceFilePath);
      } catch {}
    }
  }
}

export const defaultNonceTracker = new ApprovalNonceTracker();

export interface VerificationOptions {
  secretKey?: string;
  maxAgeMs?: number;
  nonceTracker?: ApprovalNonceTracker;
  now?: Date;
}

/**
 * Verifies that a human approval:
 * 1. Matches targeted specId, diffHash, and specHash exactly.
 * 2. Originates from an authorized SWITCH_ROOM channel.
 * 3. Has a valid timestamp (not expired, not in future).
 * 4. Has not been replayed (atomically tracked via nonceTracker).
 * 5. Possesses a valid HMAC signature computed with the secret key.
 */
export function verifyApprovalIntegrity(
  approval: HumanApproval,
  spec: RemediationSpec,
  options: VerificationOptions = {}
): { valid: boolean; reason?: string } {
  const secret = getApprovalSecret(options.secretKey);
  const maxAgeMs = options.maxAgeMs ?? DEFAULT_MAX_APPROVAL_AGE_MS;
  const tracker = options.nonceTracker ?? defaultNonceTracker;
  const now = (options.now ?? new Date()).getTime();

  if (approval.specId !== spec.id) {
    return {
      valid: false,
      reason: `Approval specId '${approval.specId}' does not match target spec '${spec.id}'`
    };
  }

  if (approval.diffHash.toLowerCase() !== spec.diffHash.toLowerCase()) {
    return {
      valid: false,
      reason: `Approval diffHash '${approval.diffHash}' does not match spec diffHash '${spec.diffHash}'`
    };
  }

  // If specHash is present in the approval or spec, verify full specification integrity
  if (approval.specHash || spec.specHash) {
    const computed = computeSpecHash(spec);
    const expectedSpecHash = approval.specHash ?? spec.specHash;
    if (computed.toLowerCase() !== expectedSpecHash?.toLowerCase()) {
      return {
        valid: false,
        reason: `Approval specHash does not match computed spec parameters (branches or verification commands were altered)`
      };
    }
  }

  if (approval.actor.channel !== 'SWITCH_ROOM') {
    return {
      valid: false,
      reason: `Approval channel '${approval.actor.channel}' is not an authorized Switch room`
    };
  }

  const approvalTime = new Date(approval.approvedAt).getTime();
  if (isNaN(approvalTime)) {
    return { valid: false, reason: 'Invalid approvedAt timestamp format' };
  }

  if (approvalTime > now + 30_000) {
    return { valid: false, reason: 'Approval timestamp is in the future' };
  }

  if (now - approvalTime > maxAgeMs) {
    return {
      valid: false,
      reason: `Approval timestamp is expired (older than ${maxAgeMs / 1000} seconds)`
    };
  }

  const expectedSignature = computeApprovalSignature(
    approval.approvalId,
    approval.specId,
    approval.diffHash,
    approval.actor.userId,
    approval.approvedAt,
    approval.nonce,
    secret,
    approval.specHash
  );

  if (approval.signature !== expectedSignature) {
    return {
      valid: false,
      reason: 'Approval signature mismatch. Possible tampering or invalid secret key'
    };
  }

  // Atomically consume the nonce (guarantees no concurrent TOCTOU race)
  const consumed = tracker.consume(approval.approvalId, approval.nonce);
  if (!consumed) {
    return {
      valid: false,
      reason: `Replay attack detected: approvalId '${approval.approvalId}' has already been processed`
    };
  }

  return { valid: true };
}

/**
 * Patterns and key names that represent sensitive credentials, tokens, or connection strings.
 */
const SENSITIVE_KEY_REGEX = /(token|api[_-]?key|secret|password|passwd|authorization|bearer|credential|jwt|private[_-]?key|client[_-]?secret|session[_-]?token|auth[_-]?header|db[_-]?pass)/i;

const SENSITIVE_VALUE_REGEXES = [
  /gh[pousr]_[A-Za-z0-9_]{36,255}/g,                                             // GitHub tokens
  /Bearer\s+[A-Za-z0-9_\-\.]{16,}/gi,                                            // Bearer tokens
  /sk-[A-Za-z0-9_\-]{20,}/g,                                                     // OpenAI/Anthropic secret keys
  /(-----BEGIN\s+([A-Z\s]+)KEY-----[\s\S]*?-----END\s+([A-Z\s]+)KEY-----)/gi,  // Full multiline PEM private keys
  /[a-zA-Z0-9+.-]+:\/\/[^:]+:[^@]+@[^\s"']+/g                                    // Connection strings with credentials
];

/**
 * Recursively scans and redacts sensitive credentials, tokens, and keys from any object.
 * Protected against circular references via a WeakSet.
 */
export function sanitizeAuditPayload(data: unknown, seen = new WeakSet<object>()): unknown {
  if (data === null || data === undefined) return data;

  if (typeof data === 'string') {
    let sanitized = data;
    for (const regex of SENSITIVE_VALUE_REGEXES) {
      sanitized = sanitized.replace(regex, '[REDACTED_CREDENTIAL]');
    }
    return sanitized;
  }

  if (typeof data === 'object') {
    if (seen.has(data as object)) {
      return '[CIRCULAR_REF]';
    }
    seen.add(data as object);

    if (Array.isArray(data)) {
      return data.map((item) => sanitizeAuditPayload(item, seen));
    }

    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(data as Record<string, unknown>)) {
      if (SENSITIVE_KEY_REGEX.test(key)) {
        result[key] = '[REDACTED]';
      } else {
        result[key] = sanitizeAuditPayload(val, seen);
      }
    }
    return result;
  }

  return data;
}

/**
 * Computes an HMAC-SHA256 (or SHA-256 if unkeyed) hash of an audit log entry for tamper evidence.
 * Using HMAC prevents attackers with file write access from rewriting the entire log file offline.
 */
export function computeAuditEntryHash(
  entry: Omit<AuditLogEntry, 'hash'>,
  secretKey?: string
): string {
  const canonicalPayload = JSON.stringify(entry.payload, Object.keys(entry.payload).sort());
  const serialized = [
    entry.id,
    entry.timestamp,
    entry.sequence.toString(),
    entry.actor.type,
    entry.actor.id,
    entry.action,
    entry.incidentId ?? '',
    entry.specId ?? '',
    canonicalPayload,
    entry.prevHash
  ].join('|');

  if (secretKey) {
    return createHmac('sha256', secretKey).update(serialized, 'utf8').digest('hex');
  }
  return createHash('sha256').update(serialized, 'utf8').digest('hex');
}
