import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import {
  IncidentMemoryRecord,
  IncidentMemoryRecordSchema,
  QuarantinedRecord,
  QuarantinedRecordSchema,
  IncidentStoreStats,
  ResolutionVerificationStatus,
  normalizeCanonicalRepository
} from './types.js';
import { normalizeErrorSignature } from './normalization.js';
import { sanitizeAuditPayload } from '../utils/crypto.js';
import { computeEvidenceHash } from './resolution-evidence.js';
import {
  ResolutionVerifier,
  StateTransitionResult,
  VerificationOptions
} from './resolution-verifier.js';

export interface IncidentStoreOptions {
  jsonlPath?: string;
  markdownPath?: string;
  quarantinePath?: string;
  autoRebuildMarkdown?: boolean;
}

export interface TransitionResolutionParams {
  canonicalRepository: string;
  incidentId: string;
  toStatus: ResolutionVerificationStatus;
  evidencePayload: unknown;
  eventId?: string;
  options?: VerificationOptions;
}

export interface TransitionResolutionResult {
  record: IncidentMemoryRecord;
  transitionResult: StateTransitionResult;
  markdownExportError?: string;
}

/**
 * Computes an unambiguous, collision-safe identity key for an incident record.
 * Uses JSON array serialization to eliminate delimiter injection attacks.
 */
export function computeIncidentIdentityKey(
  canonicalRepository: string,
  normalizedErrorSignature: string,
  diffHash: string
): string {
  return JSON.stringify([
    canonicalRepository,
    normalizedErrorSignature,
    (diffHash || '').toLowerCase()
  ]);
}

/**
 * Escapes untrusted text before insertion into Markdown documents.
 * Neutralizes Markdown syntax (headers, links, blockquotes, lists, tables, HTML tags)
 * and strips raw newlines to prevent section injection.
 */
export function escapeMarkdown(input?: string): string {
  if (!input || typeof input !== 'string') return '';
  // Collapse newlines into single spaces to prevent breaking out of single-line list entries
  const flattened = input.replace(/\r?\n/g, ' ').trim();
  // Escape Markdown syntax characters: backslash, backticks, asterisks, underscores, brackets, parentheses, hashes, blockquotes, HTML tags, pipe, tilde
  return flattened.replace(/([\\`*_{}\[\]()#<>|~])/g, '\\$1');
}

/**
 * Single-Process Authoritative Incident Memory Store.
 *
 * Design & Concurrency Contract:
 * - Single-Process Ownership: Manages data/incidents.jsonl as the authoritative source of truth.
 * - Append-Only & Transition History: Preserves complete transition records in JSONL for auditing within this service;
 *   note that JSONL files are not an independently tamper-proof distributed ledger or blockchain.
 * - Concurrency Control: All disk appends, transitions, recoveries, and markdown rebuilds are serialized via an in-memory FIFO promise lock.
 * - Crash-Safe Atomic Rewrite: Transition updates and recoveries are written to a temp file, flushed/synced, and atomically renamed over the original.
 *   If write fails, original data and in-memory indexes are strictly preserved.
 * - Durable Replay Protection: Tracks used event IDs and evidence hashes across application restarts to prevent duplicate verification events.
 * - Quarantine Protection: Malformed lines are sanitized before quarantine writing; an SHA-256 integrity fingerprint
 *   is recorded from original raw line content. (Evidence hashes and fingerprints do not independently prove source authenticity).
 * - Strict Repository Isolation: Enforced across all retrieval and transition methods.
 * - Empty Signature Duplicate Handling: When normalized error signature is empty, composite duplicate identity index is bypassed.
 * - Safe Markdown Export: All untrusted fields are escaped to prevent Markdown and HTML injection.
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

  // Durable Replay Protection Indices
  private usedEventIds = new Set<string>();
  private usedEvidenceHashes = new Set<string>();

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
   * Returns whether the incident store has completed its startup initialization.
   */
  public isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Initializes the persistent store.
   * Loads and validates all records from incidents.jsonl, heals corrupted or partial lines crash-safely,
   * preserves sanitized quarantined records with raw line integrity fingerprints, and reconstructs all in-memory indexes.
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

      // Split into lines. The line terminators (\r, \n) are excluded by the split regex,
      // but all leading, internal, and trailing whitespace within rawLine is strictly preserved.
      const lines = content.split(/\r?\n/);
      const validRecords: IncidentMemoryRecord[] = [];
      const quarantinedEntries: QuarantinedRecord[] = [];
      let hadCorruptedOrPartialLines = false;

      // Check if file content had a trailing newline
      const hasTrailingNewline = content.endsWith('\n') || content.endsWith('\r');

      for (let i = 0; i < lines.length; i++) {
        const rawLine = lines[i]!;
        if (!rawLine.trim()) continue; // Skip blank lines

        // Calculate SHA-256 integrity fingerprint from the raw line content before trimming or sanitization
        // (line terminators \r, \n are excluded from the hash as per line splitting specification)
        const rawLineHash = createHash('sha256').update(rawLine, 'utf8').digest('hex');
        const trimmed = rawLine.trim();
        const isLastLine = i === lines.length - 1;

        let parsedJson: unknown;
        try {
          parsedJson = JSON.parse(trimmed);
        } catch (jsonErr) {
          hadCorruptedOrPartialLines = true;
          const reason = isLastLine && !hasTrailingNewline
            ? `Incomplete final line (interrupted write): ${String(jsonErr)}`
            : `Malformed JSON at line ${i + 1}: ${String(jsonErr)}`;

          // Sanitize content and reason to ensure no leaked credentials in quarantine
          const sanitizedContent = sanitizeAuditPayload(trimmed) as string;
          const sanitizedReason = sanitizeAuditPayload(reason) as string;

          quarantinedEntries.push({
            id: `quar_${Date.now()}_${i + 1}`,
            quarantinedAt: new Date().toISOString(),
            reason: sanitizedReason,
            rawLineHash,
            sanitizedContent
          });
          continue;
        }

        // Validate schema
        const parseResult = IncidentMemoryRecordSchema.safeParse(parsedJson);
        if (!parseResult.success) {
          hadCorruptedOrPartialLines = true;
          const sanitizedContent = sanitizeAuditPayload(trimmed) as string;
          const reason = `Schema validation failed at line ${i + 1}: ${parseResult.error.message}`;

          quarantinedEntries.push({
            id: `quar_${Date.now()}_${i + 1}`,
            quarantinedAt: new Date().toISOString(),
            reason: sanitizeAuditPayload(reason) as string,
            rawLineHash,
            sanitizedContent
          });
          continue;
        }

        const validRecord = sanitizeIncidentRecord(parseResult.data);
        const normRepo = normalizeCanonicalRepository(validRecord.canonicalRepository);
        const normSig = normalizeErrorSignature(validRecord.errorSignature).normalizedText;

        // Reject duplicate ID during recovery (always enforced)
        if (this.idIndex.has(validRecord.id)) {
          hadCorruptedOrPartialLines = true;
          quarantinedEntries.push({
            id: `quar_${Date.now()}_${i + 1}`,
            quarantinedAt: new Date().toISOString(),
            reason: `Duplicate incident ID during startup recovery: '${validRecord.id}'`,
            rawLineHash,
            sanitizedContent: sanitizeAuditPayload(trimmed) as string
          });
          continue;
        }

        // Only enforce composite identity uniqueness when normalized error signature is non-empty.
        // Unrelated incidents with empty signatures rely solely on unique incident ID enforcement.
        let identityKey: string | null = null;
        if (normSig.length > 0) {
          identityKey = computeIncidentIdentityKey(normRepo, normSig, validRecord.diffHash);
          if (this.identityIndex.has(identityKey)) {
            hadCorruptedOrPartialLines = true;
            quarantinedEntries.push({
              id: `quar_${Date.now()}_${i + 1}`,
              quarantinedAt: new Date().toISOString(),
              reason: `Duplicate incident identity during startup recovery (matches ID: '${this.identityIndex.get(identityKey)}')`,
              rawLineHash,
              sanitizedContent: sanitizeAuditPayload(trimmed) as string
            });
            continue;
          }
        }

        // Index valid record and its history
        this.indexRecord(validRecord, normRepo, normSig, identityKey);
        validRecords.push(validRecord);
      }

      // If any corrupted lines were encountered, append them safely to quarantine
      if (quarantinedEntries.length > 0) {
        const qLines = quarantinedEntries.map((q) => JSON.stringify(q) + '\n').join('');
        await fs.appendFile(this.quarantinePath, qLines, 'utf8');
        this.quarantineCount += quarantinedEntries.length;
      }

      // Crash-Safe Atomic Rewrite: If corrupted or partial lines were healed,
      // write validated lines to a temporary file in the same directory, flush/sync, and atomically rename.
      // If recovery fails, the original authoritative file is strictly preserved.
      if (hadCorruptedOrPartialLines) {
        await this.atomicRewriteJsonl(validRecords);
      }

      // Rebuild derived Markdown export on startup to ensure it is synchronized with authoritative JSONL
      if (validRecords.length > 0 && this.autoRebuildMarkdown) {
        try {
          await this.rebuildMarkdownInternal();
        } catch {
          // If markdown export generation fails during init, do not block store initialization
        }
      }

      this.initialized = true;
    })();

    return this.initPromise;
  }

  /**
   * Appends an incident record to data/incidents.jsonl and updates all in-memory indexes.
   * Rejects duplicate IDs and duplicate identities (when normalized error signature is non-empty).
   * Serialized with atomic FIFO lock.
   */
  public async append(record: IncidentMemoryRecord): Promise<IncidentMemoryRecord> {
    await this.init();

    // 1. Validate repository format and full schema
    const normRepo = normalizeCanonicalRepository(record.canonicalRepository);
    const validated = IncidentMemoryRecordSchema.parse(record);

    // 2. Compute normalized error signature
    const normSig = normalizeErrorSignature(validated.errorSignature).normalizedText;

    // 3. Unique ID Check (always enforced)
    if (this.idIndex.has(validated.id)) {
      throw new Error(`Duplicate incident ID detected: Record with ID '${validated.id}' already exists`);
    }

    // 4. Duplicate identity check: only enforced when normalized error signature is non-empty.
    // When signature is empty, incidents must not be rejected as composite duplicates.
    let identityKey: string | null = null;
    if (normSig.length > 0) {
      identityKey = computeIncidentIdentityKey(normRepo, normSig, validated.diffHash);
      if (this.identityIndex.has(identityKey)) {
        const existingId = this.identityIndex.get(identityKey);
        throw new Error(
          `Duplicate incident record: An incident with identical repository, error signature, and diffHash already exists (ID: '${existingId}')`
        );
      }
    }

    // 5. Sanitize credentials and sensitive information
    const sanitized = sanitizeIncidentRecord(validated);

    // 6. Serialize write using atomic FIFO lock
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
        try {
          await this.rebuildMarkdownInternal();
        } catch {
          // Non-fatal: authoritative JSONL write has already succeeded; export can be regenerated on restart
        }
      }

      return structuredClone(sanitized);
    } finally {
      resolveLock();
    }
  }

  /**
   * Applies and persists a controlled resolution verification status transition.
   *
   * Guarantees:
   * - Validates repository ownership and incident identity under strict repository isolation.
   * - Evaluates transition through ResolutionVerifier before modifying any stored state.
   * - Rejects invalid, replayed, or expired transitions without modifying storage or indexes.
   * - Enforces FIFO lock serialization for concurrent transition calls.
   * - Crash-safe atomic rewrite guarantees consistency between persisted JSONL and in-memory indexes.
   * - Automatically updates derived Markdown export upon successful transition.
   */
  public async transitionResolutionStatus(params: TransitionResolutionParams): Promise<TransitionResolutionResult> {
    await this.init();

    const normRepo = normalizeCanonicalRepository(params.canonicalRepository);

    // Acquire atomic FIFO write lock
    let resolveLock!: () => void;
    const previousLock = this.writeLock;
    this.writeLock = new Promise<void>((resolve) => {
      resolveLock = resolve;
    });

    try {
      await previousLock;

      // 1. Fetch current incident record
      const currentRecord = this.idIndex.get(params.incidentId);
      if (!currentRecord) {
        throw new Error(`Incident '${params.incidentId}' not found in memory store`);
      }

      // 2. Repository ownership check (strict isolation)
      const currentRepo = normalizeCanonicalRepository(currentRecord.canonicalRepository);
      if (currentRepo !== normRepo) {
        throw new Error(
          `Repository isolation violation: Incident '${params.incidentId}' belongs to '${currentRepo}', not '${normRepo}'`
        );
      }

      // 3. Early Durable Replay Checks across store history
      if (params.eventId && this.usedEventIds.has(params.eventId)) {
        throw new Error(
          `Duplicate event ID rejected: Event ID '${params.eventId}' has already been recorded`
        );
      }

      if (params.evidencePayload) {
        try {
          const earlyEvidenceHash = computeEvidenceHash(params.evidencePayload);
          if (this.usedEvidenceHashes.has(earlyEvidenceHash.toLowerCase())) {
            throw new Error(
              `Duplicate evidence replay rejected: Evidence hash '${earlyEvidenceHash}' has already been processed`
            );
          }
        } catch (hashErr) {
          if (hashErr instanceof Error && hashErr.message.startsWith('Duplicate evidence replay rejected')) {
            throw hashErr;
          }
          // If hashing fails due to non-object/invalid payload, let ResolutionVerifier handle validation
        }
      }

      // 4. Evaluate transition through ResolutionVerifier
      const transitionResult = ResolutionVerifier.validateTransition(
        currentRecord,
        params.toStatus,
        params.evidencePayload,
        params.options
      );

      if (!transitionResult.valid) {
        throw new Error(
          `Resolution transition rejected: ${transitionResult.reasons.join('; ')}`
        );
      }

      const historyEntry = transitionResult.proposedHistoryEntry;
      if (!historyEntry) {
        throw new Error('ResolutionVerifier did not provide a valid proposed history entry');
      }

      // If caller supplied an explicit eventId, use it
      if (params.eventId) {
        historyEntry.id = params.eventId;
      }

      // 5. Post-Verification Replay Checks across store history (generated IDs & verification hashes)
      if (this.usedEventIds.has(historyEntry.id)) {
        throw new Error(
          `Duplicate event ID rejected: Event ID '${historyEntry.id}' has already been recorded`
        );
      }

      if (transitionResult.evidenceHash && this.usedEvidenceHashes.has(transitionResult.evidenceHash.toLowerCase())) {
        throw new Error(
          `Duplicate evidence replay rejected: Evidence hash '${transitionResult.evidenceHash}' has already been processed`
        );
      }

      // 6. Construct updated record
      const updatedRecord = structuredClone(currentRecord);
      updatedRecord.verificationStatus = params.toStatus;

      // Synchronize overall outcome
      if (params.toStatus === 'VERIFIED_RESOLVED') {
        updatedRecord.outcome = 'RESOLVED';
      } else if (params.toStatus === 'REGRESSED') {
        updatedRecord.outcome = 'REGRESSED';
      } else if (params.toStatus === 'PARTIAL_RESOLUTION') {
        updatedRecord.outcome = 'PARTIAL';
      }

      updatedRecord.resolutionHistory.push(historyEntry);
      const sanitizedUpdatedRecord = sanitizeIncidentRecord(updatedRecord);

      // Validate schema compliance before write
      IncidentMemoryRecordSchema.parse(sanitizedUpdatedRecord);

      // 6. Persist to authoritative store via atomic rewrite
      const allRecords = Array.from(this.idIndex.values()).map((r) =>
        r.id === sanitizedUpdatedRecord.id ? sanitizedUpdatedRecord : r
      );

      // If atomic rewrite fails, original file is preserved and in-memory indexes are NOT updated
      await this.atomicRewriteJsonl(allRecords);

      // 7. Update in-memory indexes only upon confirmed disk write
      this.idIndex.set(sanitizedUpdatedRecord.id, sanitizedUpdatedRecord);
      this.usedEventIds.add(historyEntry.id);
      if (transitionResult.evidenceHash) {
        this.usedEvidenceHashes.add(transitionResult.evidenceHash.toLowerCase());
      }

      // 8. Rebuild derived Markdown export if enabled
      let markdownExportError: string | undefined;
      if (this.autoRebuildMarkdown) {
        try {
          await this.rebuildMarkdownInternal();
        } catch (exportErr) {
          markdownExportError = `Derived Markdown export failed: ${String(exportErr)}`;
        }
      }

      return {
        record: structuredClone(sanitizedUpdatedRecord),
        transitionResult,
        ...(markdownExportError ? { markdownExportError } : {})
      };
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
    if (normSig.length === 0) return [];

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
   * exclusively from validated incident records with injection protection.
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
   * Strictly escapes untrusted incident content to prevent Markdown/HTML section injection.
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
        lines.push(`## Repository: \`${escapeMarkdown(repo)}\` (${records.length} incident${records.length === 1 ? '' : 's'})`, '');

        // Sort descending by timestamp
        const sorted = [...records].sort(
          (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
        );

        for (const rec of sorted) {
          lines.push(`### \`${rec.id}\` - [${rec.verificationStatus}]`);
          lines.push(`- **Category:** \`${rec.category}\``);
          lines.push(`- **Timestamp:** ${rec.timestamp}`);
          lines.push(`- **Target Component:** \`${escapeMarkdown(rec.affectedTarget)}\``);
          lines.push(`- **Error Signature:** ${escapeMarkdown(rec.errorSignature)}`);
          lines.push(`- **Root Cause:** ${escapeMarkdown(rec.rootCause)}`);
          lines.push(`- **Fix Summary:** ${escapeMarkdown(rec.fixSummary)}`);
          lines.push(`- **Outcome:** \`${rec.outcome}\``);
          lines.push(`- **Diff Hash:** \`${rec.diffHash}\``);
          lines.push(`- **PR Reference:** ${escapeMarkdown(rec.prLink)}`);

          if (rec.resolutionHistory && rec.resolutionHistory.length > 0) {
            lines.push('- **Resolution History:**');
            for (const h of rec.resolutionHistory) {
              const actorStr = h.actor ? ` by ${escapeMarkdown(h.actor.name)} (${escapeMarkdown(h.actor.type)})` : '';
              lines.push(
                `  - \`${h.timestamp}\` ➔ \`${h.toStatus}\`${actorStr}: ${escapeMarkdown(h.evidence)}`
              );
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
   * Atomically rewrites the authoritative JSONL file during recovery using a temporary file.
   * Flushes and syncs to disk before renaming.
   * If any step fails, cleans up the temporary file and leaves the original file untouched.
   */
  public async atomicRewriteJsonl(records: IncidentMemoryRecord[]): Promise<void> {
    const tempPath = path.join(
      path.dirname(this.jsonlPath),
      `.incidents.tmp.${Date.now()}.${randomBytes(4).toString('hex')}`
    );

    const cleanContent = records.map((r) => JSON.stringify(r)).join('\n') + (records.length > 0 ? '\n' : '');

    let fileHandle: fs.FileHandle | null = null;
    try {
      fileHandle = await fs.open(tempPath, 'w');
      await fileHandle.writeFile(cleanContent, 'utf8');
      await fileHandle.sync(); // Flush data to disk
      await fileHandle.close();
      fileHandle = null;

      // Atomic rename over destination
      await fs.rename(tempPath, this.jsonlPath);
    } catch (err) {
      if (fileHandle) {
        try {
          await fileHandle.close();
        } catch {
          // ignore close error
        }
      }
      try {
        await fs.unlink(tempPath);
      } catch {
        // ignore unlink error
      }
      throw new Error(`Crash-safe recovery failed to atomically replace authoritative store: ${String(err)}`);
    }
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
   * Only populates sigIndex and identityIndex when normSig is non-empty.
   * Indexes all resolution history event IDs and evidence hashes for durable replay protection.
   */
  private indexRecord(
    record: IncidentMemoryRecord,
    normRepo: string,
    normSig: string,
    identityKey: string | null
  ): void {
    // 1. Primary ID Index
    this.idIndex.set(record.id, record);

    // 2. Repository Index
    if (!this.repoIndex.has(normRepo)) {
      this.repoIndex.set(normRepo, new Set());
    }
    this.repoIndex.get(normRepo)!.add(record.id);

    // 3. Error Signature Index (only when non-empty)
    if (normSig.length > 0) {
      const sigKey = `${normRepo}:${normSig}`;
      if (!this.sigIndex.has(sigKey)) {
        this.sigIndex.set(sigKey, new Set());
      }
      this.sigIndex.get(sigKey)!.add(record.id);
    }

    // 4. Collision-Safe Identity Index (only when non-empty)
    if (identityKey) {
      this.identityIndex.set(identityKey, record.id);
    }

    // 5. Durable Replay Tracking (indexes all historical event IDs and evidence hashes)
    if (record.resolutionHistory && Array.isArray(record.resolutionHistory)) {
      for (const entry of record.resolutionHistory) {
        if (entry.id) {
          this.usedEventIds.add(entry.id);
        }
        if (entry.evidence) {
          const match = entry.evidence.match(/\[evidenceHash:\s*([a-f0-9]{64})\]/i);
          if (match && match[1]) {
            this.usedEvidenceHashes.add(match[1].toLowerCase());
          }
        }
      }
    }
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
