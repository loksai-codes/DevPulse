import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import {
  AuditLogEntry,
  AuditLogEntrySchema,
  AuditActor
} from '../types/audit.js';
import {
  GENESIS_HASH,
  computeAuditEntryHash,
  sanitizeAuditPayload
} from '../utils/crypto.js';

export interface AuditLoggerOptions {
  filePath: string;
}

export interface LogParams {
  actor: AuditActor;
  action: string;
  payload: Record<string, unknown>;
  incidentId?: string;
  specId?: string;
}

export interface ChainVerificationResult {
  valid: boolean;
  brokenSequence?: number;
  reason?: string;
}

export class AuditLogger extends EventEmitter {
  private filePath: string;
  private currentSequence: number = 0;
  private lastHash: string = GENESIS_HASH;
  private initPromise: Promise<void> | null = null;
  private initialized: boolean = false;
  private writeLock: Promise<void> = Promise.resolve();

  constructor(options: AuditLoggerOptions) {
    super();
    this.filePath = path.resolve(options.filePath);
  }

  /**
   * Initializes the logger safely. Concurrent callers await the same single initPromise.
   */
  public async init(): Promise<void> {
    if (this.initialized) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      await fs.mkdir(path.dirname(this.filePath), { recursive: true });

      try {
        const content = await fs.readFile(this.filePath, 'utf8');
        const lines = content.trim().split('\n').filter(Boolean);

        if (lines.length > 0) {
          const lastLine = lines[lines.length - 1];
          if (lastLine) {
            const parsed = JSON.parse(lastLine);
            const validated = AuditLogEntrySchema.parse(parsed);
            this.currentSequence = validated.sequence;
            this.lastHash = validated.hash;
          }
        }
      } catch (err: unknown) {
        const error = err as NodeJS.ErrnoException;
        if (error.code !== 'ENOENT') {
          throw error;
        }
        this.currentSequence = 0;
        this.lastHash = GENESIS_HASH;
      }

      this.initialized = true;
    })();

    return this.initPromise;
  }

  /**
   * Appends an immutable, sanitized audit entry to the JSONL log file.
   * Concurrency is strictly serialized using an atomic FIFO lock.
   */
  public async log(params: LogParams): Promise<AuditLogEntry> {
    await this.init();

    let resolveLock!: () => void;
    const previousLock = this.writeLock;
    this.writeLock = new Promise<void>((resolve) => {
      resolveLock = resolve;
    });

    try {
      await previousLock;

      const nextSequence = this.currentSequence + 1;
      const timestamp = new Date().toISOString();
      const id = randomUUID();

      // Automatically sanitize sensitive credentials, keys, and tokens
      const sanitizedPayload = sanitizeAuditPayload(params.payload) as Record<string, unknown>;

      const candidate = {
        id,
        timestamp,
        sequence: nextSequence,
        actor: params.actor,
        action: params.action,
        ...(params.incidentId ? { incidentId: params.incidentId } : {}),
        ...(params.specId ? { specId: params.specId } : {}),
        payload: sanitizedPayload,
        prevHash: this.lastHash
      };

      const entryHash = computeAuditEntryHash(candidate);

      const entry: AuditLogEntry = {
        ...candidate,
        hash: entryHash
      };

      // Validate schema compliance before write
      AuditLogEntrySchema.parse(entry);

      const line = JSON.stringify(entry) + '\n';
      await fs.appendFile(this.filePath, line, 'utf8');

      this.currentSequence = nextSequence;
      this.lastHash = entryHash;

      this.emit('entry', entry);
      return entry;
    } finally {
      resolveLock();
    }
  }

  /**
   * Reads all entries from the log file, gracefully identifying malformed lines.
   */
  public async getEntries(): Promise<{ entries: AuditLogEntry[]; error?: string; errorLine?: number }> {
    try {
      const content = await fs.readFile(this.filePath, 'utf8');
      const lines = content.trim().split('\n').filter(Boolean);
      const entries: AuditLogEntry[] = [];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        try {
          const parsed = JSON.parse(line);
          const validated = AuditLogEntrySchema.parse(parsed);
          entries.push(validated);
        } catch (parseErr: unknown) {
          const message = parseErr instanceof Error ? parseErr.message : String(parseErr);
          return {
            entries,
            error: `Malformed JSON or schema invalidity at line ${i + 1}: ${message}`,
            errorLine: i + 1
          };
        }
      }

      return { entries };
    } catch (err: unknown) {
      const error = err as NodeJS.ErrnoException;
      if (error.code === 'ENOENT') {
        return { entries: [] };
      }
      throw error;
    }
  }

  /**
   * Verifies the cryptographic integrity of the entire audit chain:
   * 1. Detects file truncation or corrupted JSON lines.
   * 2. Detects sequence gaps or sequence duplicates.
   * 3. Verifies hash chain integrity (entry[N].prevHash === entry[N-1].hash).
   * 4. Recomputes and verifies each entry's SHA-256 hash against its fields.
   */
  public async verifyChainIntegrity(): Promise<ChainVerificationResult> {
    const { entries, error, errorLine } = await this.getEntries();

    if (error) {
      return {
        valid: false,
        brokenSequence: errorLine,
        reason: `File corruption or truncation: ${error}`
      };
    }

    if (entries.length === 0) {
      return { valid: true };
    }

    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i]!;
      const expectedSequence = i + 1;

      if (entry.sequence !== expectedSequence) {
        return {
          valid: false,
          brokenSequence: entry.sequence,
          reason: `Invalid sequence at index ${i}: expected ${expectedSequence}, found ${entry.sequence}`
        };
      }

      if (entry.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          brokenSequence: entry.sequence,
          reason: `Broken hash chain at sequence ${entry.sequence}: prevHash does not match previous entry's hash`
        };
      }

      const { hash: storedHash, ...entryWithoutHash } = entry;
      const recomputedHash = computeAuditEntryHash(entryWithoutHash);

      if (storedHash !== recomputedHash) {
        return {
          valid: false,
          brokenSequence: entry.sequence,
          reason: `Data tampering detected at sequence ${entry.sequence}: recomputed hash does not match stored hash`
        };
      }

      expectedPrevHash = entry.hash;
    }

    return { valid: true };
  }

  /**
   * Resets the log (used for testing environments).
   */
  public async clear(): Promise<void> {
    try {
      await fs.unlink(this.filePath);
    } catch (err: unknown) {
      const error = err as NodeJS.ErrnoException;
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
    this.currentSequence = 0;
    this.lastHash = GENESIS_HASH;
    this.initialized = false;
    this.initPromise = null;
  }
}
