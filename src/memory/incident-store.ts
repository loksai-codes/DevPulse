import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import {
  IncidentMemoryRecord,
  IncidentMemoryRecordSchema,
  QuarantinedRecord,
  QuarantinedRecordSchema,
  IncidentStoreStats,
  normalizeCanonicalRepository
} from './types.js';
import { normalizeErrorSignature } from './normalization.js';
import { sanitizeAuditPayload } from '../utils/crypto.js';

export interface IncidentStoreOptions {
  jsonlPath?: string;
  markdownPath?: string;
  quarantinePath?: string;
  autoRebuildMarkdown?: boolean;
}

/**
 * Single-Process Authoritative Incident Memory Store.
 *
 * Design & Concurrency Contract:
 * - Single-Process Ownership: Manages data/incidents.jsonl as the sole authoritative source of truth.
 * - Concurrency Control: All disk appends, recoveries, and markdown rebuilds are serialized via an in-memory FIFO promise lock.
 * - Crash & Startup Recovery: Gracefully recovers from malformed lines and interrupted partial writes by preserving
 *   bad lines in data/incidents.quarantine.jsonl and rebuilding indexes from validated lines only.
 * - Strict Repository Isolation: Enforced across all retrieval methods.
 * - Duplicate Rejection: Atomic check for ID uniqueness and identity tuple (repo + normalizedSignature + diffHash).
 * - Sensitive Data Redaction: Automatic redaction of credentials, tokens, and keys before persisting or exporting.
 */
export class IncidentStore {
  private jsonlPath: string;
  private markdownPath: string;
  private quarantinePath: string;
  private autoRebuildMarkdown: boolean;

  // In-Memory Index Structures
  private idIndex = new Map<string, IncidentMemoryRecord>();
  private repoIndex = new Map<string, Set<string>>();
  private sigIndex = new Map<string, Set<string>>();
  private identityIndex = new Map<string, string>(); // identityKey -> id

  private quarantineCount: number = 0;
  private initialized: boolean = false;
  private initPromise: Promise<void> | null = null;
  private writeLock: Promise<void> = Promise.resolve();

  constructor(options: IncidentStoreOptions = {}) {
    this.jsonlPath = path.resolve(options.jsonlPath ?? './data/incidents.jsonl');
    this.markdownPath = path.resolve(options.markdownPath ?? './data/incidents.md');
    this.quarantinePath = path.resolve(options.quarantinePath ?? './data/incidents.quarantine.jsonl');
    this.autoRebuildMarkdown = options.autoRebuildMarkdown ?? true;
  }

  /**
   * Initializes the persistent store.
   * Loads and validates all records from incidents.jsonl, heals corrupted or partial lines,
   * preserves quarantined records, and reconstructs all in-memory indexes.
   */
  public async init(): Promise<void> {
    if (this.initialized) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      // Ensure parent directories exist
      await fs.mkdir(path.dirname(this.jsonlPath), { recursive: true });
      await fs.mkdir(path.dirname(this.markdownPath), { recursive: true });
      await fs.mkdir(path.dirname(this.quarantinePath), { recursive: true });

      // Count existing quarantined records if quarantine file exists
      try {
        const qContent = await fs.readFile(this.quarantinePath, 'utf8');
        this.quarantineCount = qContent.trim().split(/\r?\n/).filter(Boolean).length;
      } catch (err: unknown) {
        const error = err as NodeJS.ErrnoException;
        if (error.code !== 'ENOENT') throw error;
        this.quarantineCount = 0;
      }

      // Read authoritative JSONL file
      let content = '';
      try {
        content = await fs.readFile(this.jsonlPath, 'utf8');
      } catch (err: unknown) {
        const error = err as NodeJS.ErrnoException;
        if (error.code !== 'ENOENT') throw error;
        // File does not exist yet; initialize empty
        this.initialized = true;
        return;
      }

      const lines = content.split(/\r?\n/);
      const validRecords: IncidentMemoryRecord[] = [];
      const quarantinedEntries: QuarantinedRecord[] = [];
      let hadCorruptedOrPartialLines = false;

      // Check if file content was truncated without a trailing newline
      // (a non-empty file without trailing \n could be an incomplete write)
      const hasTrailingNewline = content.endsWith('\n') || content.endsWith('\r');

      for (let i = 0; i < lines.length; i++) {
        const rawLine = lines[i]!;
        const trimmed = rawLine.trim();
        if (!trimmed) continue;

        // If it is the last line and there was no trailing newline, verify carefully
        const isLastLine = i === lines.length - 1;

        const rawLineHash = createHash('sha256').update(trimmed, 'utf8').digest('hex');
        const sanitizedContent = sanitizeAuditPayload(trimmed) as string;

        let parsedJson: unknown;
        try {
          parsedJson = JSON.parse(trimmed);
        } catch (jsonErr) {
          hadCorruptedOrPartialLines = true;
          const reason = isLastLine && !hasTrailingNewline
            ? `Incomplete final line (interrupted write): ${String(jsonErr)}`
            : `Malformed JSON at line ${i + 1}: ${String(jsonErr)}`;

          quarantinedEntries.push({
            id: `quar_${Date.now()}_${i + 1}`,
            quarantinedAt: new Date().toISOString(),
            reason,
            rawLineHash,
            sanitizedContent
          });
          continue;
        }

        // Validate schema
        const parseResult = IncidentMemoryRecordSchema.safeParse(parsedJson);
        if (!parseResult.success) {
          hadCorruptedOrPartialLines = true;
          quarantinedEntries.push({
            id: `quar_${Date.now()}_${i + 1}`,
            quarantinedAt: new Date().toISOString(),
            reason: `Schema validation failed at line ${i + 1}: ${parseResult.error.message}`,
            rawLineHash,
            sanitizedContent
          });
          continue;
        }

        const validRecord = sanitizeIncidentRecord(parseResult.data);
        const normRepo = normalizeCanonicalRepository(validRecord.canonicalRepository);
        const normSig = normalizeErrorSignature(validRecord.errorSignature).normalizedText;
        const identityKey = `${normRepo}:${normSig}:${validRecord.diffHash.toLowerCase()}`;

        // Reject duplicate ID or identity during recovery
        if (this.idIndex.has(validRecord.id)) {
          hadCorruptedOrPartialLines = true;
          quarantinedEntries.push({
            id: `quar_${Date.now()}_${i + 1}`,
            quarantinedAt: new Date().toISOString(),
            reason: `Duplicate incident ID during startup recovery: '${validRecord.id}'`,
            rawLineHash,
            sanitizedContent
          });
          continue;
        }

        if (this.identityIndex.has(identityKey)) {
          hadCorruptedOrPartialLines = true;
          quarantinedEntries.push({
            id: `quar_${Date.now()}_${i + 1}`,
            quarantinedAt: new Date().toISOString(),
            reason: `Duplicate incident identity during startup recovery (matches ID: '${this.identityIndex.get(identityKey)}')`,
            rawLineHash,
            sanitizedContent
          });
          continue;
        }

        // Index valid record
        this.indexRecord(validRecord, normRepo, normSig, identityKey);
        validRecords.push(validRecord);
      }

      // If any corrupted lines were encountered, write them to quarantine and heal authoritative file
      if (quarantinedEntries.length > 0) {
        const qLines = quarantinedEntries.map((q) => JSON.stringify(q) + '\n').join('');
        await fs.appendFile(this.quarantinePath, qLines, 'utf8');
        this.quarantineCount += quarantinedEntries.length;
      }

      if (hadCorruptedOrPartialLines) {
        // Rewrite authoritative file containing ONLY validated records
        const cleanContent = validRecords.map((r) => JSON.stringify(r)).join('\n') + (validRecords.length > 0 ? '\n' : '');
        await fs.writeFile(this.jsonlPath, cleanContent, 'utf8');
      }

      // If markdown export doesn't exist yet and records exist, generate it
      try {
        await fs.access(this.markdownPath);
      } catch {
        if (validRecords.length > 0 && this.autoRebuildMarkdown) {
          await this.rebuildMarkdownInternal();
        }
      }

      this.initialized = true;
    })();

    return this.initPromise;
  }

  /**
   * Appends an incident record to data/incidents.jsonl and updates all in-memory indexes.
   * Rejects duplicate IDs and duplicate identities.
   * Serialized with atomic FIFO lock.
   */
  public async append(record: IncidentMemoryRecord): Promise<IncidentMemoryRecord> {
    await this.init();

    // 1. Validate repository format and full schema
    const normRepo = normalizeCanonicalRepository(record.canonicalRepository);
    const validated = IncidentMemoryRecordSchema.parse(record);

    // 2. Compute identity key: repo + normalized error signature + diffHash
    const normSig = normalizeErrorSignature(validated.errorSignature).normalizedText;
    const identityKey = `${normRepo}:${normSig}:${validated.diffHash.toLowerCase()}`;

    // 3. Duplicate checks
    if (this.idIndex.has(validated.id)) {
      throw new Error(`Duplicate incident ID detected: Record with ID '${validated.id}' already exists`);
    }

    if (this.identityIndex.has(identityKey)) {
      const existingId = this.identityIndex.get(identityKey);
      throw new Error(
        `Duplicate incident record: An incident with identical repository, error signature, and diffHash already exists (ID: '${existingId}')`
      );
    }

    // 4. Sanitize credentials and sensitive information
    const sanitized = sanitizeIncidentRecord(validated);

    // 5. Serialize write using atomic FIFO lock
    let resolveLock!: () => void;
    const previousLock = this.writeLock;
    this.writeLock = new Promise<void>((resolve) => {
      resolveLock = resolve;
    });

    try {
      await previousLock;

      // Format JSON line with terminating newline
      const line = JSON.stringify(sanitized) + '\n';

      // Atomic file write - if this throws, memory indexes remain unmodified
      await fs.appendFile(this.jsonlPath, line, 'utf8');

      // Update in-memory indexes only upon confirmed disk write
      this.indexRecord(sanitized, normRepo, normSig, identityKey);

      // Rebuild derived Markdown export if enabled
      if (this.autoRebuildMarkdown) {
        await this.rebuildMarkdownInternal();
      }

      return structuredClone(sanitized);
    } finally {
      resolveLock();
    }
  }

  /**
   * Retrieves an incident record by ID enforcing strict repository isolation.
   */
  public getById(canonicalRepository: string, id: string): IncidentMemoryRecord | null {
    const normRepo = normalizeCanonicalRepository(canonicalRepository);
    const record = this.idIndex.get(id);
    if (!record) return null;

    if (normalizeCanonicalRepository(record.canonicalRepository) !== normRepo) {
      return null; // Cross-repository access rejected
    }

    return structuredClone(record);
  }

  /**
   * Lists all incident records belonging to the specified repository.
   */
  public listByRepository(canonicalRepository: string): IncidentMemoryRecord[] {
    const normRepo = normalizeCanonicalRepository(canonicalRepository);
    const ids = this.repoIndex.get(normRepo);
    if (!ids || ids.size === 0) return [];

    const results: IncidentMemoryRecord[] = [];
    for (const id of ids) {
      const rec = this.idIndex.get(id);
      if (rec) results.push(structuredClone(rec));
    }
    return results;
  }

  /**
   * Finds incident records matching a normalized error signature within a specific repository.
   */
  public findBySignature(canonicalRepository: string, rawSignature: string): IncidentMemoryRecord[] {
    const normRepo = normalizeCanonicalRepository(canonicalRepository);
    const normSig = normalizeErrorSignature(rawSignature).normalizedText;
    const key = `${normRepo}:${normSig}`;

    const ids = this.sigIndex.get(key);
    if (!ids || ids.size === 0) return [];

    const results: IncidentMemoryRecord[] = [];
    for (const id of ids) {
      const rec = this.idIndex.get(id);
      if (rec) results.push(structuredClone(rec));
    }
    return results;
  }

  /**
   * Rebuilds the derived human-readable Markdown export (data/incidents.md)
   * exclusively from validated incident records.
   */
  public async rebuildMarkdown(): Promise<string> {
    await this.init();

    let resolveLock!: () => void;
    const previousLock = this.writeLock;
    this.writeLock = new Promise<void>((resolve) => {
      resolveLock = resolve;
    });

    try {
      await previousLock;
      return await this.rebuildMarkdownInternal();
    } finally {
      resolveLock();
    }
  }

  /**
   * Internal markdown generation without re-acquiring outer writeLock.
   */
  private async rebuildMarkdownInternal(): Promise<string> {
    const allRecords = Array.from(this.idIndex.values());

    // Group records by canonical repository
    const grouped = new Map<string, IncidentMemoryRecord[]>();
    for (const rec of allRecords) {
      const repo = rec.canonicalRepository;
      if (!grouped.has(repo)) grouped.set(repo, []);
      grouped.get(repo)!.push(rec);
    }

    const lines: string[] = [
      '# DevPulse Incident Memory Store',
      '',
      '> *Authoritative Source: `data/incidents.jsonl` | Auto-generated export — do not edit manually.*  ',
      `> *Last Rebuilt: ${new Date().toISOString()} | Total Records: ${allRecords.length}*`,
      '',
      '---',
      ''
    ];

    if (grouped.size === 0) {
      lines.push('*(No incident records stored yet)*', '');
    } else {
      for (const [repo, records] of grouped) {
        lines.push(`## Repository: \`${repo}\` (${records.length} incident${records.length === 1 ? '' : 's'})`, '');

        // Sort descending by timestamp
        const sorted = [...records].sort(
          (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
        );

        for (const rec of sorted) {
          lines.push(`### \`${rec.id}\` - [${rec.verificationStatus}]`);
          lines.push(`- **Category:** \`${rec.category}\``);
          lines.push(`- **Timestamp:** \`${rec.timestamp}\``);
          lines.push(`- **Target Component:** \`${rec.affectedTarget}\``);
          lines.push(`- **Error Signature:** \`${rec.errorSignature}\``);
          lines.push(`- **Root Cause:** ${rec.rootCause}`);
          lines.push(`- **Fix Summary:** ${rec.fixSummary}`);
          lines.push(`- **Outcome:** \`${rec.outcome}\``);
          lines.push(`- **Diff Hash:** \`${rec.diffHash}\``);
          lines.push(`- **PR Reference:** ${rec.prLink}`);

          if (rec.resolutionHistory && rec.resolutionHistory.length > 0) {
            lines.push('- **Resolution History:**');
            for (const h of rec.resolutionHistory) {
              const actorStr = h.actor ? ` by ${h.actor.name} (${h.actor.type})` : '';
              lines.push(`  - \`${h.timestamp}\` ➔ \`${h.toStatus}\`${actorStr}: ${h.evidence}`);
            }
          }

          lines.push('');
        }
      }
    }

    const markdownContent = lines.join('\n');
    await fs.writeFile(this.markdownPath, markdownContent, 'utf8');
    return markdownContent;
  }

  /**
   * Returns current statistics of the memory store.
   */
  public getStats(): IncidentStoreStats {
    const repos: Record<string, number> = {};
    for (const [repo, ids] of this.repoIndex) {
      repos[repo] = ids.size;
    }

    return {
      totalRecords: this.idIndex.size,
      repositories: repos,
      quarantineCount: this.quarantineCount
    };
  }

  /**
   * Reads all quarantined entries for administrative inspection.
   */
  public async getQuarantinedRecords(): Promise<QuarantinedRecord[]> {
    try {
      const content = await fs.readFile(this.quarantinePath, 'utf8');
      const lines = content.trim().split(/\r?\n/).filter(Boolean);
      const results: QuarantinedRecord[] = [];
      for (const line of lines) {
        try {
          const parsed = JSON.parse(line);
          results.push(QuarantinedRecordSchema.parse(parsed));
        } catch {
          // ignore corrupted lines inside quarantine itself
        }
      }
      return results;
    } catch (err: unknown) {
      const error = err as NodeJS.ErrnoException;
      if (error.code === 'ENOENT') return [];
      throw error;
    }
  }

  /**
   * Indexes a validated record in all in-memory map structures.
   */
  private indexRecord(
    record: IncidentMemoryRecord,
    normRepo: string,
    normSig: string,
    identityKey: string
  ): void {
    // 1. Primary ID Index
    this.idIndex.set(record.id, record);

    // 2. Repository Index
    if (!this.repoIndex.has(normRepo)) {
      this.repoIndex.set(normRepo, new Set());
    }
    this.repoIndex.get(normRepo)!.add(record.id);

    // 3. Error Signature Index
    const sigKey = `${normRepo}:${normSig}`;
    if (!this.sigIndex.has(sigKey)) {
      this.sigIndex.set(sigKey, new Set());
    }
    this.sigIndex.get(sigKey)!.add(record.id);

    // 4. Identity Index
    this.identityIndex.set(identityKey, record.id);
  }
}

/**
 * Recursively redacts sensitive credentials, tokens, bearer keys, and secrets from an incident record.
 */
export function sanitizeIncidentRecord(record: IncidentMemoryRecord): IncidentMemoryRecord {
  const clone = structuredClone(record);

  clone.errorSignature = sanitizeAuditPayload(clone.errorSignature) as string;
  clone.rootCause = sanitizeAuditPayload(clone.rootCause) as string;
  clone.fixSummary = sanitizeAuditPayload(clone.fixSummary) as string;
  clone.prLink = sanitizeAuditPayload(clone.prLink) as string;

  if (clone.metadata) {
    clone.metadata = sanitizeAuditPayload(clone.metadata) as Record<string, unknown>;
  }

  if (clone.resolutionHistory && clone.resolutionHistory.length > 0) {
    clone.resolutionHistory = clone.resolutionHistory.map((h) => ({
      ...h,
      evidence: sanitizeAuditPayload(h.evidence) as string
    }));
  }

  return clone;
}

