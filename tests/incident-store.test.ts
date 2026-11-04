import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { createHash } from 'node:crypto';
import {
  IncidentStore,
  IncidentMemoryRecord,
  computeIncidentIdentityKey,
  escapeMarkdown
} from '../src/memory/index.js';

describe('Sub-Stage 4.3.2: Persistent Incident Store', () => {
  let tempDir: string;
  let jsonlPath: string;
  let markdownPath: string;
  let quarantinePath: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'devpulse-memory-test-'));
    jsonlPath = path.join(tempDir, 'incidents.jsonl');
    markdownPath = path.join(tempDir, 'incidents.md');
    quarantinePath = path.join(tempDir, 'incidents.quarantine.jsonl');
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  const sampleRecord1: IncidentMemoryRecord = {
    id: 'INC-2026-101',
    canonicalRepository: 'devpulse/core',
    timestamp: '2026-11-04T12:00:00.000Z',
    category: 'RUNTIME_EXCEPTION',
    errorSignature: 'TypeError: Cannot read properties of undefined (reading token)',
    affectedTarget: 'src/auth/jwt.ts',
    rootCause: 'Unchecked null payload in token parser',
    fixSummary: 'Added optional chaining before reading token',
    diffHash: 'a'.repeat(64),
    prLink: 'https://github.com/devpulse/core/pull/101',
    outcome: 'RESOLVED',
    verificationStatus: 'VERIFIED_RESOLVED',
    resolutionHistory: [
      {
        id: 'RH-1',
        toStatus: 'VERIFIED_RESOLVED',
        timestamp: '2026-11-04T12:10:00.000Z',
        evidence: 'PR #101 merged and all tests passed'
      }
    ]
  };

  const sampleRecord2: IncidentMemoryRecord = {
    id: 'INC-2026-102',
    canonicalRepository: 'devpulse/runner',
    timestamp: '2026-11-04T13:00:00.000Z',
    category: 'BUILD_FAILURE',
    errorSignature: 'error TS2307: Cannot find module @devpulse/types',
    affectedTarget: 'src/runner/exec.ts',
    rootCause: 'Missing build dependency in package.json',
    fixSummary: 'Added @devpulse/types to dependencies',
    diffHash: 'b'.repeat(64),
    prLink: 'https://github.com/devpulse/runner/pull/42',
    outcome: 'RESOLVED',
    verificationStatus: 'VERIFIED_RESOLVED',
    resolutionHistory: []
  };

  describe('1. Append and Retrieve Incident Records', () => {
    it('appends and retrieves records by ID, repository, and signature', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();

      await store.append(sampleRecord1);
      await store.append(sampleRecord2);

      // 1. Retrieve by ID with repository isolation
      const retrieved = store.getById('devpulse/core', 'INC-2026-101');
      assert.ok(retrieved !== null);
      assert.equal(retrieved.id, 'INC-2026-101');
      assert.equal(retrieved.canonicalRepository, 'devpulse/core');
      assert.equal(retrieved.verificationStatus, 'VERIFIED_RESOLVED');

      // 2. List by Repository
      const coreList = store.listByRepository('devpulse/core');
      assert.equal(coreList.length, 1);
      assert.equal(coreList[0]?.id, 'INC-2026-101');

      const runnerList = store.listByRepository('devpulse/runner');
      assert.equal(runnerList.length, 1);
      assert.equal(runnerList[0]?.id, 'INC-2026-102');

      // 3. Find by Signature (normalized)
      const sigMatches = store.findBySignature(
        'devpulse/core',
        'TypeError: Cannot read properties of undefined (reading token)'
      );
      assert.equal(sigMatches.length, 1);
      assert.equal(sigMatches[0]?.id, 'INC-2026-101');
    });
  });

  describe('2. Persistence Across Restart & Index Reconstruction', () => {
    it('persists records to disk and reconstructs all in-memory indexes on reload', async () => {
      // Step 1: Write records with store 1
      const store1 = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store1.init();
      await store1.append(sampleRecord1);
      await store1.append(sampleRecord2);

      const stats1 = store1.getStats();
      assert.equal(stats1.totalRecords, 2);

      // Step 2: Create new store instance pointing to same file path
      const store2 = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store2.init();

      const stats2 = store2.getStats();
      assert.equal(stats2.totalRecords, 2);
      assert.equal(stats2.repositories['devpulse/core'], 1);
      assert.equal(stats2.repositories['devpulse/runner'], 1);

      // Verify that all indexes were reconstructed and functional
      const rec = store2.getById('devpulse/core', 'INC-2026-101');
      assert.ok(rec !== null);
      assert.equal(rec.id, 'INC-2026-101');

      const bySig = store2.findBySignature(
        'devpulse/core',
        'TypeError: Cannot read properties of undefined (reading token) [pid: 9999]'
      );
      assert.equal(bySig.length, 1);
      assert.equal(bySig[0]?.id, 'INC-2026-101');
    });
  });

  describe('3. Duplicate Prevention & Collision Safety', () => {
    it('rejects duplicate incident IDs with descriptive error', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append(sampleRecord1);

      // Attempt appending duplicate ID
      const duplicateIdRecord: IncidentMemoryRecord = {
        ...sampleRecord2,
        id: 'INC-2026-101' // Same ID as sampleRecord1
      };

      await assert.rejects(
        async () => await store.append(duplicateIdRecord),
        /Duplicate incident ID detected/
      );
    });

    it('rejects duplicate incident identity (repository + normalized signature + diffHash)', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append(sampleRecord1);

      // Different ID, but same repository, same normalized signature, and same diffHash
      const duplicateIdentityRecord: IncidentMemoryRecord = {
        ...sampleRecord1,
        id: 'INC-2026-DIFFERENT-ID',
        errorSignature: 'TypeError: Cannot read properties of undefined (reading token) [pid: 9999]'
      };

      await assert.rejects(
        async () => await store.append(duplicateIdentityRecord),
        /Duplicate incident record/
      );
    });

    it('demonstrates tuple identity keys prevent delimiter collision attacks', () => {
      // Delimiter collision scenario:
      // If we used a colon delimiter `${repo}:${sig}:${diffHash}`:
      // Case A: repo = "devpulse/core:sub", sig = "err", diffHash = "abc" -> "devpulse/core:sub:err:abc"
      // Case B: repo = "devpulse/core", sig = "sub:err", diffHash = "abc" -> "devpulse/core:sub:err:abc" (COLLISION!)
      const keyA = computeIncidentIdentityKey('devpulse/core:sub', 'err', 'abc');
      const keyB = computeIncidentIdentityKey('devpulse/core', 'sub:err', 'abc');

      assert.notEqual(keyA, keyB);
      assert.equal(keyA, JSON.stringify(['devpulse/core:sub', 'err', 'abc']));
      assert.equal(keyB, JSON.stringify(['devpulse/core', 'sub:err', 'abc']));
    });

    it('does not reject unrelated incidents with empty normalized signatures as duplicates, while enforcing unique IDs', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();

      // Incident A has an error signature whose normalized text is empty
      const emptySigRecordA: IncidentMemoryRecord = {
        ...sampleRecord1,
        id: 'INC-EMPTY-SIG-A',
        errorSignature: '---'
      };

      // Incident B is an unrelated incident in the same repo, with same diffHash, also normalizing to empty signature
      const emptySigRecordB: IncidentMemoryRecord = {
        ...sampleRecord1,
        id: 'INC-EMPTY-SIG-B',
        errorSignature: '...'
      };

      // Both must append successfully without false composite duplicate rejection
      await store.append(emptySigRecordA);
      await store.append(emptySigRecordB);

      assert.equal(store.getStats().totalRecords, 2);
      assert.ok(store.getById('devpulse/core', 'INC-EMPTY-SIG-A') !== null);
      assert.ok(store.getById('devpulse/core', 'INC-EMPTY-SIG-B') !== null);

      // But duplicate ID check must still be strictly enforced
      await assert.rejects(
        async () => await store.append(emptySigRecordA),
        /Duplicate incident ID detected/
      );
    });
  });

  describe('4. Cross-Repository Isolation', () => {
    it('strictly isolates incidents: retrieving an ID under the wrong repository returns null', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append(sampleRecord1); // devpulse/core

      // Try looking up core's incident under runner's repository
      const crossLookup = store.getById('devpulse/runner', 'INC-2026-101');
      assert.equal(crossLookup, null);

      // Signature query under wrong repository yields empty array
      const crossSig = store.findBySignature('devpulse/runner', sampleRecord1.errorSignature);
      assert.equal(crossSig.length, 0);

      // Empty list for repository without records
      const nonExistentList = store.listByRepository('other-org/other-repo');
      assert.equal(nonExistentList.length, 0);
    });
  });

  describe('5. Startup Recovery, Quarantine & Credential Protection', () => {
    it('recovers from malformed JSON and quarantines bad lines with SHA-256 integrity hash', async () => {
      const validLine = JSON.stringify(sampleRecord1);
      const malformedLine = '{ malformed json line without closing bracket ';
      const schemaInvalidLine = JSON.stringify({ id: 'INC-BAD', errorSignature: 'Missing required fields' });

      const corruptedContent = `${validLine}\n${malformedLine}\n${schemaInvalidLine}\n`;
      await fs.writeFile(jsonlPath, corruptedContent, 'utf8');

      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();

      // Valid record should be recovered
      const stats = store.getStats();
      assert.equal(stats.totalRecords, 1);
      assert.equal(stats.quarantineCount, 2);

      const recovered = store.getById('devpulse/core', 'INC-2026-101');
      assert.ok(recovered !== null);

      // Authoritative file must be cleaned to valid records only
      const cleanedFileContent = await fs.readFile(jsonlPath, 'utf8');
      assert.ok(!cleanedFileContent.includes('malformed json line'));

      // Quarantine file must contain the preserved bad lines with rawLineHash
      const quarantined = await store.getQuarantinedRecords();
      assert.equal(quarantined.length, 2);
      assert.ok(quarantined.some((q) => q.sanitizedContent.includes('malformed json line')));
      assert.ok(quarantined.some((q) => q.sanitizedContent.includes('INC-BAD')));

      // Check SHA-256 integrity fingerprint (preserving whitespace, excluding line terminator)
      const expectedHash = createHash('sha256').update(malformedLine, 'utf8').digest('hex');
      const malformedQuarantine = quarantined.find((q) => q.sanitizedContent.includes('malformed json line'));
      assert.equal(malformedQuarantine?.rawLineHash, expectedHash);
    });

    it('verifies quarantine rawLineHash integrity fingerprint preserves leading and trailing whitespace', async () => {
      // Line with deliberate leading spaces and trailing tabs/spaces
      const untrimmedLine = '   { malformed: json with leading/trailing whitespace } \t ';
      await fs.writeFile(jsonlPath, `${untrimmedLine}\n`, 'utf8');

      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();

      const quarantined = await store.getQuarantinedRecords();
      assert.equal(quarantined.length, 1);

      // Verify rawLineHash matches the exact untrimmed string (line terminator \n excluded)
      const expectedFingerprint = createHash('sha256').update(untrimmedLine, 'utf8').digest('hex');
      assert.equal(quarantined[0]?.rawLineHash, expectedFingerprint);

      // Verify trimmed and sanitized content is stored separately
      assert.ok(quarantined[0]?.sanitizedContent.includes('{ malformed: json with leading/trailing whitespace }'));
    });

    it('sanitizes credentials inside malformed JSON records before writing to quarantine', async () => {
      const rawSecretLine =
        '{"id": "INC-MALFORMED", token: "ghp_123456789012345678901234567890123456", pass: "postgres://admin:superSecretPass@db.internal:5432/main"}';

      await fs.writeFile(jsonlPath, `${rawSecretLine}\n`, 'utf8');

      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();

      const quarantined = await store.getQuarantinedRecords();
      assert.equal(quarantined.length, 1);

      const entry = quarantined[0]!;
      // Verify rawLineHash matches the raw line
      const expectedHash = createHash('sha256').update(rawSecretLine.trim(), 'utf8').digest('hex');
      assert.equal(entry.rawLineHash, expectedHash);

      // Verify sanitizedContent has redacted the sensitive tokens
      assert.ok(!entry.sanitizedContent.includes('ghp_'));
      assert.ok(!entry.sanitizedContent.includes('superSecretPass'));
      assert.ok(entry.sanitizedContent.includes('[REDACTED_CREDENTIAL]'));

      // Verify the physical quarantine file on disk contains NO raw secrets
      const rawQuarantineFile = await fs.readFile(quarantinePath, 'utf8');
      assert.ok(!rawQuarantineFile.includes('ghp_'));
      assert.ok(!rawQuarantineFile.includes('superSecretPass'));
    });

    it('recovers from incomplete final line (interrupted crash write) and quarantines it', async () => {
      const validLine = JSON.stringify(sampleRecord1);
      const incompleteLine = '{"id":"INC-CRASH","canonicalRepository":"devpulse/core"';
      const fileWithPartial = `${validLine}\n${incompleteLine}`;
      await fs.writeFile(jsonlPath, fileWithPartial, 'utf8');

      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();

      assert.equal(store.getStats().totalRecords, 1);
      assert.equal(store.getStats().quarantineCount, 1);

      const quarantined = await store.getQuarantinedRecords();
      assert.equal(quarantined.length, 1);
      assert.ok(quarantined[0]?.reason.includes('Incomplete final line'));
      assert.equal(quarantined[0]?.sanitizedContent, incompleteLine);
    });
  });

  describe('6. Crash-Safe Recovery & Write Failure Handling', () => {
    it('leaves in-memory indexes unmodified if disk write fails', async () => {
      const store = new IncidentStore({
        jsonlPath,
        markdownPath,
        quarantinePath
      });
      await store.init();

      // Simulate a disk I/O failure on appendFile
      const originalAppendFile = fs.appendFile;
      try {
        (fs as unknown as { appendFile: typeof fs.appendFile }).appendFile = async () => {
          throw new Error('Disk I/O failure (simulated ENOSPC)');
        };

        await assert.rejects(
          async () => await store.append(sampleRecord1),
          /Disk I\/O failure \(simulated ENOSPC\)/
        );

        // In-memory index must remain 0 and unmodified
        assert.equal(store.getStats().totalRecords, 0);
        assert.equal(store.getById('devpulse/core', 'INC-2026-101'), null);
      } finally {
        (fs as unknown as { appendFile: typeof fs.appendFile }).appendFile = originalAppendFile;
      }
    });

    it('preserves the original authoritative file if atomic rewrite fails during recovery', async () => {
      const originalContent = `${JSON.stringify(sampleRecord1)}\n{ malformed line }\n`;
      await fs.writeFile(jsonlPath, originalContent, 'utf8');

      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });

      // Simulate a failure during fs.rename
      const originalRename = fs.rename;
      try {
        (fs as unknown as { rename: typeof fs.rename }).rename = async () => {
          throw new Error('Permission denied during atomic rename');
        };

        await assert.rejects(
          async () => await store.init(),
          /Crash-safe recovery failed to atomically replace authoritative store/
        );

        // Verify the original file was NOT truncated or destroyed
        const intactContent = await fs.readFile(jsonlPath, 'utf8');
        assert.equal(intactContent, originalContent);
      } finally {
        (fs as unknown as { rename: typeof fs.rename }).rename = originalRename;
      }
    });
  });

  describe('7. Safe Derived Markdown Export & Injection Protection', () => {
    it('generates derived human-readable Markdown export from JSONL', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append(sampleRecord1);
      await store.append(sampleRecord2);

      const mdContent = await fs.readFile(markdownPath, 'utf8');
      assert.ok(mdContent.includes('# DevPulse Incident Memory Store'));
      assert.ok(mdContent.includes('## Repository: `devpulse/core`'));
      assert.ok(mdContent.includes('## Repository: `devpulse/runner`'));
      assert.ok(mdContent.includes('### `INC-2026-101` - [VERIFIED_RESOLVED]'));
      assert.ok(mdContent.includes('### `INC-2026-102` - [VERIFIED_RESOLVED]'));

      // Test manual rebuild
      const rebuilt = await store.rebuildMarkdown();
      assert.ok(rebuilt.includes('devpulse/core'));
      assert.ok(rebuilt.includes('devpulse/runner'));
    });

    it('escapes Markdown injection vectors (headings, links, blockquotes, HTML tags)', async () => {
      const maliciousRecord: IncidentMemoryRecord = {
        ...sampleRecord1,
        id: 'INC-MALICIOUS',
        errorSignature: 'Error: Fake Header\n## Injected Section\n> Injected Quote',
        rootCause: 'Normal cause\n[Malicious Link](https://attacker.com)\n<script>alert("xss")</script>',
        fixSummary: 'Fixed\n- Injected List Item\n| Injected | Table |',
        prLink: 'https://github.com/devpulse/core/pull/1#section',
        diffHash: 'c'.repeat(64)
      };

      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append(maliciousRecord);

      const mdContent = await fs.readFile(markdownPath, 'utf8');

      // 1. Headings must be escaped
      assert.ok(!mdContent.includes('\n## Injected Section'));
      assert.ok(mdContent.includes('\\#\\# Injected Section'));

      // 2. Links must be escaped
      assert.ok(!mdContent.includes('[Malicious Link](https://attacker.com)'));
      assert.ok(mdContent.includes('\\[Malicious Link\\]\\(https://attacker.com\\)'));

      // 3. HTML tags must be escaped
      assert.ok(!mdContent.includes('<script>'));
      assert.ok(mdContent.includes('\\<script\\>'));

      // 4. Blockquotes and lists must be escaped
      assert.ok(!mdContent.includes('\n> Injected Quote'));
      assert.ok(mdContent.includes('\\> Injected Quote'));
    });

    it('unit tests escapeMarkdown utility for diverse syntax characters', () => {
      assert.equal(escapeMarkdown('# Header'), '\\# Header');
      assert.equal(escapeMarkdown('[link](url)'), '\\[link\\]\\(url\\)');
      assert.equal(escapeMarkdown('<div id="test">'), '\\<div id="test"\\>');
      assert.equal(escapeMarkdown('line1\nline2'), 'line1 line2');
      assert.equal(escapeMarkdown(''), '');
    });
  });

  describe('8. Sensitive Credential Redaction', () => {
    it('redacts tokens, bearer headers, and connection strings before persisting to JSONL or Markdown', async () => {
      const sensitiveRecord: IncidentMemoryRecord = {
        ...sampleRecord1,
        id: 'INC-2026-SECRET',
        errorSignature: 'AuthFailed: Invalid token ghp_123456789012345678901234567890123456 at login',
        rootCause: 'Connection failed to postgres://admin:superSecret123@db.internal:5432/main',
        fixSummary: 'Rotated Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret and updated secrets',
        prLink: 'https://github.com/devpulse/core/pull/999?token=secretTokenVal',
        metadata: {
          apiKey: 'sk-123456789012345678901234567890'
        }
      };

      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      const saved = await store.append(sensitiveRecord);

      // Verify returned object is redacted
      assert.ok(!saved.errorSignature.includes('ghp_'));
      assert.ok(saved.errorSignature.includes('[REDACTED_CREDENTIAL]'));
      assert.ok(!saved.rootCause.includes('superSecret123'));
      assert.ok(saved.rootCause.includes('[REDACTED_CREDENTIAL]'));
      assert.ok(!saved.fixSummary.includes('eyJhbGci'));
      assert.ok(saved.fixSummary.includes('[REDACTED_CREDENTIAL]'));
      assert.equal((saved.metadata as Record<string, unknown>)?.['apiKey'], '[REDACTED]');

      // Verify authoritative JSONL file on disk is also redacted
      const fileContent = await fs.readFile(jsonlPath, 'utf8');
      assert.ok(!fileContent.includes('ghp_'));
      assert.ok(!fileContent.includes('superSecret123'));
      assert.ok(!fileContent.includes('eyJhbGci'));

      // Verify Markdown export is also redacted
      const mdContent = await fs.readFile(markdownPath, 'utf8');
      assert.ok(!mdContent.includes('ghp_'));
      assert.ok(!mdContent.includes('superSecret123'));
      assert.ok(!mdContent.includes('eyJhbGci'));
    });
  });

  describe('9. Resolution Transition Persistence & Controlled State Machine', () => {
    const partialEvidence = {
      incidentId: 'INC-2026-101',
      canonicalRepository: 'devpulse/core',
      mitigatedAt: '2026-11-04T12:15:00.000Z',
      mitigationScope: 'Applied rate limit and token cache workaround',
      remainingDefects: 'Core JWT library parser still needs permanent upstream patch',
      provenance: {
        source: 'SWITCH_ROOM' as const,
        sourceReference: 'msg_mitigate_001',
        capturedAt: '2026-11-04T12:15:00.000Z',
        verificationType: 'USER_PROVIDED' as const,
        evidenceHash: '4'.repeat(64),
        capturedBy: {
          type: 'HUMAN' as const,
          id: 'user_alice',
          name: 'Alice Maintainer'
        }
      }
    };

    const fullBundle = {
      incidentId: 'INC-2026-101',
      canonicalRepository: 'devpulse/core',
      pr: {
        prNumber: 101,
        prUrl: 'https://github.com/devpulse/core/pull/101',
        baseBranch: 'main',
        mergeCommitSha: '5'.repeat(40),
        mergedAt: '2026-11-04T12:20:00.000Z',
        mergedBy: 'alice',
        provenance: {
          source: 'GITHUB_API' as const,
          sourceReference: 'https://api.github.com/repos/devpulse/core/pulls/101',
          capturedAt: '2026-11-04T12:20:00.000Z',
          verificationType: 'INDEPENDENTLY_VERIFIED' as const,
          evidenceHash: '5'.repeat(64)
        }
      },
      diff: {
        proposedDiffHash: 'a'.repeat(64),
        actualMergedDiffHash: 'a'.repeat(64),
        isReconciled: false
      },
      regressionTests: {
        testSuiteName: 'tests/auth.test.ts',
        command: 'npm test -- tests/auth.test.ts',
        executedAt: '2026-11-04T12:22:00.000Z',
        durationMs: 300,
        totalTests: 10,
        passedTests: 10,
        failedTests: 0,
        skippedTests: 0,
        outputLogHash: '6'.repeat(64),
        provenance: {
          source: 'CI_CD_PIPELINE' as const,
          sourceReference: 'run_101',
          capturedAt: '2026-11-04T12:22:00.000Z',
          verificationType: 'INDEPENDENTLY_VERIFIED' as const,
          evidenceHash: '6'.repeat(64)
        }
      },
      confirmation: {
        confirmedAt: '2026-11-04T12:25:00.000Z',
        observabilityEvidence: {
          metricOrLogRef: 'datadog://monitors/auth_error_rate',
          observedAt: '2026-11-04T12:25:00.000Z',
          sampleProof: '0.00% 5xx errors across all pods for 30 minutes',
          provenance: {
            source: 'OBSERVABILITY_SYSTEM' as const,
            sourceReference: 'dash_auth',
            capturedAt: '2026-11-04T12:25:00.000Z',
            verificationType: 'INDEPENDENTLY_VERIFIED' as const,
            evidenceHash: '7'.repeat(64)
          }
        },
        provenance: {
          source: 'OBSERVABILITY_SYSTEM' as const,
          sourceReference: 'dash_auth',
          capturedAt: '2026-11-04T12:25:00.000Z',
          verificationType: 'INDEPENDENTLY_VERIFIED' as const,
          evidenceHash: '7'.repeat(64)
        }
      }
    };

    it('persists valid transitions and updates JSONL store and Markdown export', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      // Start as UNVERIFIED_PROPOSAL
      await store.append({ ...sampleRecord1, verificationStatus: 'UNVERIFIED_PROPOSAL', resolutionHistory: [] });

      // Step 1: Transition to PARTIAL_RESOLUTION
      const step1 = await store.transitionResolutionStatus({
        canonicalRepository: 'devpulse/core',
        incidentId: 'INC-2026-101',
        toStatus: 'PARTIAL_RESOLUTION',
        evidencePayload: partialEvidence,
        options: { now: new Date('2026-11-04T12:16:00.000Z') }
      });

      assert.equal(step1.record.verificationStatus, 'PARTIAL_RESOLUTION');
      assert.equal(step1.record.outcome, 'PARTIAL');
      assert.equal(step1.record.resolutionHistory.length, 1);
      assert.equal(step1.record.resolutionHistory[0]?.toStatus, 'PARTIAL_RESOLUTION');

      // Step 2: Transition from PARTIAL_RESOLUTION to VERIFIED_RESOLVED
      const step2 = await store.transitionResolutionStatus({
        canonicalRepository: 'devpulse/core',
        incidentId: 'INC-2026-101',
        toStatus: 'VERIFIED_RESOLVED',
        evidencePayload: fullBundle,
        options: { now: new Date('2026-11-04T12:26:00.000Z') }
      });

      assert.equal(step2.record.verificationStatus, 'VERIFIED_RESOLVED');
      assert.equal(step2.record.outcome, 'RESOLVED');
      assert.equal(step2.record.resolutionHistory.length, 2);

      // Verify authoritative JSONL file on disk was updated
      const fileContent = await fs.readFile(jsonlPath, 'utf8');
      const lines = fileContent.trim().split('\n');
      assert.equal(lines.length, 1);
      const parsedRecord = JSON.parse(lines[0]!);
      assert.equal(parsedRecord.verificationStatus, 'VERIFIED_RESOLVED');
      assert.equal(parsedRecord.resolutionHistory.length, 2);

      // Verify Markdown export reflects the new status badge and history
      const mdContent = await fs.readFile(markdownPath, 'utf8');
      assert.ok(mdContent.includes('### `INC-2026-101` - [VERIFIED_RESOLVED]'));
      assert.ok(mdContent.includes('Verified resolution merged in PR \\#101'));
    });

    it('rejects invalid transitions without modifying stored data', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append({ ...sampleRecord1, verificationStatus: 'UNVERIFIED_PROPOSAL', resolutionHistory: [] });

      // Attempt forbidden transition: UNVERIFIED_PROPOSAL -> VERIFIED_RESOLVED with missing PR
      const incompleteBundle = {
        ...fullBundle,
        pr: undefined
      };

      await assert.rejects(
        async () =>
          await store.transitionResolutionStatus({
            canonicalRepository: 'devpulse/core',
            incidentId: 'INC-2026-101',
            toStatus: 'VERIFIED_RESOLVED',
            evidencePayload: incompleteBundle
          }),
        /Resolution transition rejected/
      );

      // Verify record in store and on disk remained UNVERIFIED_PROPOSAL with 0 history entries
      const current = store.getById('devpulse/core', 'INC-2026-101');
      assert.equal(current?.verificationStatus, 'UNVERIFIED_PROPOSAL');
      assert.equal(current?.resolutionHistory.length, 0);

      const fileContent = await fs.readFile(jsonlPath, 'utf8');
      const parsedRecord = JSON.parse(fileContent.trim());
      assert.equal(parsedRecord.verificationStatus, 'UNVERIFIED_PROPOSAL');
    });

    it('enforces FIFO serialization for concurrent transitions', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append({ ...sampleRecord1, verificationStatus: 'UNVERIFIED_PROPOSAL', resolutionHistory: [] });

      // Create two sequential transitions
      const t1 = store.transitionResolutionStatus({
        canonicalRepository: 'devpulse/core',
        incidentId: 'INC-2026-101',
        toStatus: 'PARTIAL_RESOLUTION',
        evidencePayload: partialEvidence,
        options: { now: new Date('2026-11-04T12:16:00.000Z') }
      });

      const t2 = store.transitionResolutionStatus({
        canonicalRepository: 'devpulse/core',
        incidentId: 'INC-2026-101',
        toStatus: 'VERIFIED_RESOLVED',
        evidencePayload: fullBundle,
        options: { now: new Date('2026-11-04T12:26:00.000Z') }
      });

      const [res1, res2] = await Promise.all([t1, t2]);
      assert.equal(res1.record.verificationStatus, 'PARTIAL_RESOLUTION');
      assert.equal(res2.record.verificationStatus, 'VERIFIED_RESOLVED');
      assert.equal(res2.record.resolutionHistory.length, 2);
    });

    it('rejects duplicate evidence replays and duplicate event IDs', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append({ ...sampleRecord1, verificationStatus: 'UNVERIFIED_PROPOSAL', resolutionHistory: [] });

      // First transition succeeds
      await store.transitionResolutionStatus({
        canonicalRepository: 'devpulse/core',
        incidentId: 'INC-2026-101',
        toStatus: 'PARTIAL_RESOLUTION',
        evidencePayload: partialEvidence,
        eventId: 'evt_custom_001',
        options: { now: new Date('2026-11-04T12:16:00.000Z') }
      });

      // Transition to VERIFIED_RESOLVED succeeds
      await store.transitionResolutionStatus({
        canonicalRepository: 'devpulse/core',
        incidentId: 'INC-2026-101',
        toStatus: 'VERIFIED_RESOLVED',
        evidencePayload: fullBundle,
        options: { now: new Date('2026-11-04T12:26:00.000Z') }
      });

      // Attempt 1: Replay fullBundle evidence
      await assert.rejects(
        async () =>
          await store.transitionResolutionStatus({
            canonicalRepository: 'devpulse/core',
            incidentId: 'INC-2026-101',
            toStatus: 'VERIFIED_RESOLVED',
            evidencePayload: fullBundle
          }),
        /Duplicate evidence replay rejected/
      );

      // Attempt 2: Replay custom eventId 'evt_custom_001'
      const freshPartialEvidence = {
        ...partialEvidence,
        mitigatedAt: '2026-11-04T12:28:00.000Z',
        provenance: { ...partialEvidence.provenance, evidenceHash: '8'.repeat(64) }
      };

      await assert.rejects(
        async () =>
          await store.transitionResolutionStatus({
            canonicalRepository: 'devpulse/core',
            incidentId: 'INC-2026-101',
            toStatus: 'PARTIAL_RESOLUTION',
            evidencePayload: freshPartialEvidence,
            eventId: 'evt_custom_001' // Duplicate eventId
          }),
        /Duplicate event ID rejected/
      );
    });

    it('preserves status, history, and durable replay protection across store restarts', async () => {
      // Step 1: Write transitions with store 1
      const store1 = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store1.init();
      await store1.append({ ...sampleRecord1, verificationStatus: 'UNVERIFIED_PROPOSAL', resolutionHistory: [] });

      await store1.transitionResolutionStatus({
        canonicalRepository: 'devpulse/core',
        incidentId: 'INC-2026-101',
        toStatus: 'PARTIAL_RESOLUTION',
        evidencePayload: partialEvidence,
        options: { now: new Date('2026-11-04T12:16:00.000Z') }
      });

      await store1.transitionResolutionStatus({
        canonicalRepository: 'devpulse/core',
        incidentId: 'INC-2026-101',
        toStatus: 'VERIFIED_RESOLVED',
        evidencePayload: fullBundle,
        options: { now: new Date('2026-11-04T12:26:00.000Z') }
      });

      // Step 2: Create new store instance pointing to same file path (simulating restart)
      const store2 = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store2.init();

      const reloaded = store2.getById('devpulse/core', 'INC-2026-101');
      assert.ok(reloaded !== null);
      assert.equal(reloaded.verificationStatus, 'VERIFIED_RESOLVED');
      assert.equal(reloaded.resolutionHistory.length, 2);

      // Verify that previously used evidence hash is STILL blocked on the restarted store!
      await assert.rejects(
        async () =>
          await store2.transitionResolutionStatus({
            canonicalRepository: 'devpulse/core',
            incidentId: 'INC-2026-101',
            toStatus: 'VERIFIED_RESOLVED',
            evidencePayload: fullBundle
          }),
        /Duplicate evidence replay rejected/
      );
    });

    it('leaves in-memory indexes and stored data unmodified if atomic write fails during transition', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append({ ...sampleRecord1, verificationStatus: 'UNVERIFIED_PROPOSAL', resolutionHistory: [] });

      // Monkeypatch atomicRewriteJsonl to simulate a disk I/O failure
      const originalAtomicRewrite = store.atomicRewriteJsonl.bind(store);
      store.atomicRewriteJsonl = async () => {
        throw new Error('Simulated atomic rewrite failure (disk full)');
      };

      try {
        await assert.rejects(
          async () =>
            await store.transitionResolutionStatus({
              canonicalRepository: 'devpulse/core',
              incidentId: 'INC-2026-101',
              toStatus: 'PARTIAL_RESOLUTION',
              evidencePayload: partialEvidence,
              eventId: 'evt_fail_999',
              options: { now: new Date('2026-11-04T12:16:00.000Z') }
            }),
          /Simulated atomic rewrite failure/
        );

        // Verify in-memory record remained UNVERIFIED_PROPOSAL with 0 history entries
        const record = store.getById('devpulse/core', 'INC-2026-101');
        assert.equal(record?.verificationStatus, 'UNVERIFIED_PROPOSAL');
        assert.equal(record?.resolutionHistory.length, 0);

        // Verify replay-protection indexes were NOT contaminated:
        // When disk write is restored, retrying with the EXACT same eventId and evidence succeeds
        store.atomicRewriteJsonl = originalAtomicRewrite;
        const retryResult = await store.transitionResolutionStatus({
          canonicalRepository: 'devpulse/core',
          incidentId: 'INC-2026-101',
          toStatus: 'PARTIAL_RESOLUTION',
          evidencePayload: partialEvidence,
          eventId: 'evt_fail_999',
          options: { now: new Date('2026-11-04T12:16:00.000Z') }
        });

        assert.equal(retryResult.record.verificationStatus, 'PARTIAL_RESOLUTION');
        assert.equal(retryResult.record.resolutionHistory.length, 1);
        assert.equal(retryResult.record.resolutionHistory[0]?.id, 'evt_fail_999');
      } finally {
        store.atomicRewriteJsonl = originalAtomicRewrite;
      }
    });

    it('handles Markdown export failure gracefully while committing JSONL and regenerates on restart', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append({ ...sampleRecord1, verificationStatus: 'UNVERIFIED_PROPOSAL', resolutionHistory: [] });

      // Simulate failure specifically when writing the Markdown export
      const originalWriteFile = fs.writeFile;
      let simulateMarkdownFailure = true;

      (fs as unknown as { writeFile: typeof fs.writeFile }).writeFile = async (
        file: Parameters<typeof fs.writeFile>[0],
        data: Parameters<typeof fs.writeFile>[1],
        options?: Parameters<typeof fs.writeFile>[2]
      ) => {
        if (simulateMarkdownFailure && typeof file === 'string' && file.endsWith('.md')) {
          throw new Error('EACCES: permission denied, open markdown file');
        }
        return (originalWriteFile as Function)(file, data, options);
      };

      try {
        // Transition should NOT throw despite Markdown failure
        const result = await store.transitionResolutionStatus({
          canonicalRepository: 'devpulse/core',
          incidentId: 'INC-2026-101',
          toStatus: 'PARTIAL_RESOLUTION',
          evidencePayload: partialEvidence,
          options: { now: new Date('2026-11-04T12:16:00.000Z') }
        });

        // 1. Authoritative JSONL transition is committed
        assert.equal(result.record.verificationStatus, 'PARTIAL_RESOLUTION');
        const inMemory = store.getById('devpulse/core', 'INC-2026-101');
        assert.equal(inMemory?.verificationStatus, 'PARTIAL_RESOLUTION');

        const jsonlContent = await fs.readFile(jsonlPath, 'utf8');
        const parsed = JSON.parse(jsonlContent.trim().split('\n')[0]!);
        assert.equal(parsed.verificationStatus, 'PARTIAL_RESOLUTION');

        // 2. Export failure is reported accurately in the result
        assert.ok(result.markdownExportError);
        assert.ok(result.markdownExportError.includes('Derived Markdown export failed'));
        assert.ok(result.markdownExportError.includes('EACCES'));

        // 3. Store restart successfully regenerates the Markdown export
        simulateMarkdownFailure = false;
        const restartedStore = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
        await restartedStore.init();

        const mdContent = await fs.readFile(markdownPath, 'utf8');
        assert.ok(mdContent.includes('### `INC-2026-101` - [PARTIAL_RESOLUTION]'));
      } finally {
        (fs as unknown as { writeFile: typeof fs.writeFile }).writeFile = originalWriteFile;
      }
    });

    it('verifies Windows atomic replacement over existing file, cleans up temporary files, and preserves original on rename failure', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append({ ...sampleRecord1, verificationStatus: 'UNVERIFIED_PROPOSAL', resolutionHistory: [] });

      const originalJsonlContent = await fs.readFile(jsonlPath, 'utf8');
      assert.ok(originalJsonlContent.length > 0);

      // 1. Successful atomic replacement over an existing file
      const updatedRecord: IncidentMemoryRecord = {
        ...sampleRecord1,
        verificationStatus: 'VERIFIED_RESOLVED',
        outcome: 'RESOLVED',
        resolutionHistory: []
      };

      await store.atomicRewriteJsonl([updatedRecord]);
      const replacedContent = await fs.readFile(jsonlPath, 'utf8');
      assert.notEqual(replacedContent, originalJsonlContent);
      assert.ok(replacedContent.includes('VERIFIED_RESOLVED'));

      // Check no temp files leaked
      const dirFiles = await fs.readdir(path.dirname(jsonlPath));
      const tempFilesAfterSuccess = dirFiles.filter((f) => f.startsWith('.incidents.tmp.'));
      assert.equal(tempFilesAfterSuccess.length, 0);

      // 2. Failure during atomic rename: original file must be preserved and temp file unlinked
      const originalRename = fs.rename;
      try {
        (fs as unknown as { rename: typeof fs.rename }).rename = async () => {
          throw new Error('EPERM: operation not permitted, rename');
        };

        const failedRecord: IncidentMemoryRecord = {
          ...sampleRecord1,
          verificationStatus: 'REGRESSED',
          resolutionHistory: []
        };

        await assert.rejects(
          async () => await store.atomicRewriteJsonl([failedRecord]),
          /Crash-safe recovery failed to atomically replace authoritative store: Error: EPERM/
        );

        // Original file must remain unchanged
        const preservedContent = await fs.readFile(jsonlPath, 'utf8');
        assert.equal(preservedContent, replacedContent);
        assert.ok(!preservedContent.includes('REGRESSED'));

        // All temporary files must be unlinked and cleaned up
        const dirFilesAfterFail = await fs.readdir(path.dirname(jsonlPath));
        const tempFilesAfterFail = dirFilesAfterFail.filter((f) => f.startsWith('.incidents.tmp.'));
        assert.equal(tempFilesAfterFail.length, 0);
      } finally {
        (fs as unknown as { rename: typeof fs.rename }).rename = originalRename;
      }
    });

    it('enforces repository isolation during resolution transition', async () => {
      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();
      await store.append({ ...sampleRecord1, verificationStatus: 'UNVERIFIED_PROPOSAL', resolutionHistory: [] });

      // Attempt transition under wrong repository
      await assert.rejects(
        async () =>
          await store.transitionResolutionStatus({
            canonicalRepository: 'devpulse/runner', // Wrong repo (incident belongs to devpulse/core)
            incidentId: 'INC-2026-101',
            toStatus: 'PARTIAL_RESOLUTION',
            evidencePayload: partialEvidence
          }),
        /Repository isolation violation/
      );
    });
  });
});
