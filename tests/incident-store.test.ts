import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  IncidentStore,
  IncidentMemoryRecord,
  sanitizeIncidentRecord
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

  describe('3. Duplicate Prevention', () => {
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
        // Slight surface variation that normalizes to identical text:
        errorSignature: 'TypeError: Cannot read properties of undefined (reading token) [pid: 9999]'
      };

      await assert.rejects(
        async () => await store.append(duplicateIdentityRecord),
        /Duplicate incident record/
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

  describe('5. Startup Recovery & Quarantine Preservation', () => {
    it('recovers from malformed JSON and quarantines bad lines without discarding them', async () => {
      // Pre-seed JSONL file with 1 valid record, 1 malformed JSON line, and 1 schema-invalid line
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

      // Quarantine file must contain the preserved bad lines
      const quarantined = await store.getQuarantinedRecords();
      assert.equal(quarantined.length, 2);
      assert.ok(quarantined.some((q) => q.rawContent.includes('malformed json line')));
      assert.ok(quarantined.some((q) => q.rawContent.includes('INC-BAD')));
    });

    it('recovers from incomplete final line (interrupted crash write) and quarantines it', async () => {
      const validLine = JSON.stringify(sampleRecord1);
      // Incomplete partial line without trailing newline
      const incompleteLine = '{"id":"INC-CRASH","canonicalRepository":"devpulse/core"';
      const fileWithPartial = `${validLine}\n${incompleteLine}`; // Notice no trailing newline
      await fs.writeFile(jsonlPath, fileWithPartial, 'utf8');

      const store = new IncidentStore({ jsonlPath, markdownPath, quarantinePath });
      await store.init();

      assert.equal(store.getStats().totalRecords, 1);
      assert.equal(store.getStats().quarantineCount, 1);

      const quarantined = await store.getQuarantinedRecords();
      assert.equal(quarantined.length, 1);
      assert.ok(quarantined[0]?.reason.includes('Incomplete final line'));
      assert.equal(quarantined[0]?.rawContent, incompleteLine);
    });
  });

  describe('6. Write Failure Handling', () => {
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
  });

  describe('7. Derived Markdown Export & Rebuild', () => {
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
});
