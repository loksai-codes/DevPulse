import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { AuditLogger } from '../src/audit/audit-logger.js';
import { GENESIS_HASH } from '../src/utils/crypto.js';

describe('AuditLogger (Append-Only JSONL with Hash Chaining)', () => {
  const testLogPath = path.resolve('./logs/test-audit.jsonl');
  let logger: AuditLogger;

  beforeEach(async () => {
    logger = new AuditLogger({ filePath: testLogPath });
    await logger.clear();
  });

  afterEach(async () => {
    await logger.clear();
  });

  it('initializes clean log with genesis state', async () => {
    await logger.init();
    const { entries } = await logger.getEntries();
    assert.equal(entries.length, 0);

    const check = await logger.verifyChainIntegrity();
    assert.equal(check.valid, true);
  });

  it('records sequential audit entries with monotonic sequence numbers and hash chains', async () => {
    const entry1 = await logger.log({
      actor: { type: 'SENTINEL', id: 'agent-sentinel', name: 'Sentinel' },
      action: 'INCIDENT_DETECTED',
      payload: { issueNumber: 42, error: 'NullPointer' },
      incidentId: 'INC-42'
    });

    assert.equal(entry1.sequence, 1);
    assert.equal(entry1.prevHash, GENESIS_HASH);
    assert.match(entry1.hash, /^[a-f0-9]{64}$/);

    const entry2 = await logger.log({
      actor: { type: 'PATCH_RUNNER', id: 'agent-runner', name: 'Patch Runner' },
      action: 'WORKTREE_PREPARED',
      payload: { branch: 'devpulse/fix-42' },
      incidentId: 'INC-42'
    });

    assert.equal(entry2.sequence, 2);
    assert.equal(entry2.prevHash, entry1.hash);

    const entry3 = await logger.log({
      actor: { type: 'HUMAN', id: 'usr_alice', name: 'Alice' },
      action: 'HUMAN_APPROVAL_RECORDED',
      payload: { decision: 'APPROVED' },
      incidentId: 'INC-42'
    });

    assert.equal(entry3.sequence, 3);
    assert.equal(entry3.prevHash, entry2.hash);

    const verification = await logger.verifyChainIntegrity();
    assert.equal(verification.valid, true);
  });

  it('detects tampering if an audit record in the file is modified', async () => {
    await logger.log({
      actor: { type: 'SENTINEL', id: 'agent-sentinel', name: 'Sentinel' },
      action: 'INCIDENT_DETECTED',
      payload: { score: 10 }
    });

    await logger.log({
      actor: { type: 'HUMAN', id: 'usr_bob', name: 'Bob' },
      action: 'HUMAN_APPROVAL_RECORDED',
      payload: { decision: 'APPROVED' }
    });

    // Tamper with file directly on disk
    const rawContent = await fs.readFile(testLogPath, 'utf8');
    const tamperedContent = rawContent.replace('"APPROVED"', '"REJECTED"');
    await fs.writeFile(testLogPath, tamperedContent, 'utf8');

    const result = await logger.verifyChainIntegrity();
    assert.equal(result.valid, false);
    assert.equal(result.brokenSequence, 2);
    assert.match(result.reason!, /Data tampering detected/);
  });

  it('resumes monotonic sequence and hash chaining after logger restart', async () => {
    await logger.log({
      actor: { type: 'SYSTEM', id: 'sys', name: 'System' },
      action: 'BOOTSTRAP',
      payload: { version: '0.1.0' }
    });

    // Create a new logger instance pointing to the existing file
    const restartedLogger = new AuditLogger({ filePath: testLogPath });
    await restartedLogger.init();

    const resumedEntry = await restartedLogger.log({
      actor: { type: 'SENTINEL', id: 'agent-sentinel', name: 'Sentinel' },
      action: 'RESUMED_AFTER_RESTART',
      payload: { active: true }
    });

    assert.equal(resumedEntry.sequence, 2);
    const verification = await restartedLogger.verifyChainIntegrity();
    assert.equal(verification.valid, true);
  });

  it('emits entry events for real-time subscribers', async () => {
    let capturedEvent: unknown = null;
    logger.on('entry', (entry) => {
      capturedEvent = entry;
    });

    const created = await logger.log({
      actor: { type: 'SYSTEM', id: 'sys', name: 'System' },
      action: 'STREAM_TEST',
      payload: { test: true }
    });

    assert.deepEqual(capturedEvent, created);
  });
});
