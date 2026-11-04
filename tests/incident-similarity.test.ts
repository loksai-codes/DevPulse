import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeErrorSignature,
  normalizeTargetComponent,
  normalizeStackFrames,
  calculateJaccardSimilarity,
  evaluateIncidentSimilarity,
  rankHistoricalMatches,
  IncidentMemoryRecord,
  IncidentMemoryQuery,
  IncidentMemoryRecordSchema,
  CanonicalRepositorySchema,
  HistoricalIncidentMatch,
  isValidCanonicalRepository,
  normalizeCanonicalRepository
} from '../src/memory/index.js';

describe('Sub-Stage 4.3.1: Incident Normalization & Similarity Engine', () => {
  describe('Error Signature & Target Component Normalization', () => {
    it('strips memory addresses, timestamps, process IDs, UUIDs, and line numbers from signatures', () => {
      const raw = 'TypeError [ERR_INVALID_ARG]: Failed at 0x7fff5fbff8c0 [pid: 43210] at 2026-11-04T12:00:00Z in module.ts:42:15 id: 12345678-1234-1234-1234-123456789abc';
      const normalized = normalizeErrorSignature(raw);

      assert.ok(!normalized.normalizedText.includes('0x7fff5fbff8c0'));
      assert.ok(!normalized.normalizedText.includes('2026-11-04t12:00:00z'));
      assert.ok(!normalized.normalizedText.includes('43210'));
      assert.ok(!normalized.normalizedText.includes('12345678-1234-1234-1234-123456789abc'));
      assert.ok(!normalized.normalizedText.includes(':42:15'));
      assert.equal(normalized.errorType, 'TypeError');
      assert.ok(normalized.tokens.has('typeerror'));
      assert.ok(normalized.tokens.has('invalid'));
      assert.ok(normalized.tokens.has('arg'));
      assert.ok(normalized.tokens.has('failed'));
    });

    it('handles empty, null, or whitespace signature gracefully', () => {
      const emptyResult = normalizeErrorSignature('');
      assert.equal(emptyResult.normalizedText, '');
      assert.equal(emptyResult.tokens.size, 0);
      assert.equal(emptyResult.errorType, undefined);

      const whitespaceResult = normalizeErrorSignature('   ');
      assert.equal(whitespaceResult.normalizedText, '');
      assert.equal(whitespaceResult.tokens.size, 0);
    });

    it('normalizes target file paths across operating system separators', () => {
      const winPath = normalizeTargetComponent('.\\src\\auth\\token-manager.ts');
      const unixPath = normalizeTargetComponent('/src/auth/token-manager.ts');

      assert.equal(winPath.normalizedPath, 'src/auth/token-manager.ts');
      assert.equal(unixPath.normalizedPath, 'src/auth/token-manager.ts');
      assert.deepEqual(winPath.segments, ['src', 'auth', 'token-manager.ts']);
      assert.ok(winPath.tokens.has('auth'));
      assert.ok(winPath.tokens.has('token'));
      assert.ok(winPath.tokens.has('manager'));
    });

    it('normalizes stack frames ignoring line and column coordinates', () => {
      const frames = [
        {
          raw: 'at verifyToken (src/auth/token.ts:55:12)',
          file: 'src/auth/token.ts',
          line: 55,
          column: 12,
          functionName: 'verifyToken',
          isProjectSource: true,
          isDependency: false,
          isRuntimeInternal: false
        },
        {
          raw: 'at handleRequest (src/server.ts:120:5)',
          file: 'src\\server.ts',
          line: 120,
          column: 5,
          functionName: 'handleRequest',
          isProjectSource: true,
          isDependency: false,
          isRuntimeInternal: false
        }
      ];

      const normalized = normalizeStackFrames(frames);
      assert.equal(normalized.frameDescriptors.length, 2);
      assert.equal(normalized.frameDescriptors[0], 'src/auth/token.ts:verifytoken');
      assert.equal(normalized.frameDescriptors[1], 'src/server.ts:handlerequest');
      assert.ok(normalized.tokens.has('verifytoken'));
      assert.ok(normalized.tokens.has('server'));
    });
  });

  describe('Deterministic Jaccard Similarity', () => {
    it('computes exact 1.0 for identical non-empty sets', () => {
      const setA = new Set(['auth', 'token', 'expired']);
      const setB = new Set(['auth', 'token', 'expired']);
      assert.equal(calculateJaccardSimilarity(setA, setB), 1.0);
    });

    it('computes 0.0 for completely disjoint sets', () => {
      const setA = new Set(['apple', 'banana']);
      const setB = new Set(['orange', 'grape']);
      assert.equal(calculateJaccardSimilarity(setA, setB), 0.0);
    });

    it('computes exact intersection over union for partial overlaps', () => {
      const setA = new Set(['a', 'b', 'c']);
      const setB = new Set(['b', 'c', 'd']);
      // Intersection: {b, c} (2), Union: {a, b, c, d} (4) -> 2/4 = 0.5000
      assert.equal(calculateJaccardSimilarity(setA, setB), 0.5);
    });

    it('returns 0.0 when either or both sets are empty (missing info never matches)', () => {
      const emptyA = new Set<string>();
      const emptyB = new Set<string>();
      const populated = new Set(['test']);

      assert.equal(calculateJaccardSimilarity(emptyA, emptyB), 0.0);
      assert.equal(calculateJaccardSimilarity(emptyA, populated), 0.0);
      assert.equal(calculateJaccardSimilarity(populated, emptyB), 0.0);
    });
  });

  describe('Canonical Repository Validation & Normalization', () => {
    it('validates and normalizes valid canonical repositories', () => {
      assert.equal(isValidCanonicalRepository('devpulse/core'), true);
      assert.equal(isValidCanonicalRepository('org-123/my.project_v2'), true);
      assert.equal(isValidCanonicalRepository('facebook/react'), true);
      assert.equal(isValidCanonicalRepository('a/b'), true);

      assert.equal(normalizeCanonicalRepository('DevPulse/Core'), 'devpulse/core');
      assert.equal(normalizeCanonicalRepository('My-Org/Project.JS'), 'my-org/project.js');
    });

    it('rejects path traversal segments in repository identifier', () => {
      assert.equal(isValidCanonicalRepository('../core'), false);
      assert.equal(isValidCanonicalRepository('devpulse/..'), false);
      assert.equal(isValidCanonicalRepository('devpulse/../core'), false);
      assert.equal(isValidCanonicalRepository('..'), false);
      assert.throws(() => CanonicalRepositorySchema.parse('../core'));
      assert.throws(() => CanonicalRepositorySchema.parse('devpulse/..'));
    });

    it('rejects dot-only segments and leading/trailing dots in repository identifier', () => {
      assert.equal(isValidCanonicalRepository('./core'), false);
      assert.equal(isValidCanonicalRepository('devpulse/.'), false);
      assert.equal(isValidCanonicalRepository('.devpulse/core'), false);
      assert.equal(isValidCanonicalRepository('devpulse./core'), false);
      assert.equal(isValidCanonicalRepository('devpulse/.core'), false);
      assert.equal(isValidCanonicalRepository('devpulse/core.'), false);
      assert.throws(() => CanonicalRepositorySchema.parse('.devpulse/core'));
      assert.throws(() => CanonicalRepositorySchema.parse('devpulse/core.'));
    });

    it('rejects whitespace, tabs, and newlines in repository identifier', () => {
      assert.equal(isValidCanonicalRepository(' devpulse/core'), false);
      assert.equal(isValidCanonicalRepository('devpulse/core '), false);
      assert.equal(isValidCanonicalRepository('devpulse / core'), false);
      assert.equal(isValidCanonicalRepository('devpulse/\tcore'), false);
      assert.throws(() => CanonicalRepositorySchema.parse('devpulse / core'));
    });

    it('rejects URL fragments, query parameters, schemes, and ports in repository identifier', () => {
      assert.equal(isValidCanonicalRepository('devpulse/core#main'), false);
      assert.equal(isValidCanonicalRepository('devpulse/core?branch=main'), false);
      assert.equal(isValidCanonicalRepository('https://github.com/devpulse/core'), false);
      assert.equal(isValidCanonicalRepository('git@github.com:devpulse/core'), false);
      assert.throws(() => CanonicalRepositorySchema.parse('devpulse/core#main'));
    });

    it('rejects invalid separators (backslashes, multiple slashes, extra subpaths)', () => {
      assert.equal(isValidCanonicalRepository('devpulse\\core'), false);
      assert.equal(isValidCanonicalRepository('devpulse//core'), false);
      assert.equal(isValidCanonicalRepository('devpulse/core/submodule'), false);
      assert.throws(() => CanonicalRepositorySchema.parse('devpulse\\core'));
    });
  });

  describe('Repository Isolation Contract', () => {
    const sampleRecord: IncidentMemoryRecord = {
      id: 'INC-2026-001',
      canonicalRepository: 'devpulse/core',
      timestamp: '2026-11-04T10:00:00.000Z',
      category: 'RUNTIME_EXCEPTION',
      errorSignature: 'TypeError: Cannot read properties of undefined (reading verify)',
      affectedTarget: 'src/auth/jwt.ts',
      rootCause: 'Unchecked null reference in verifyToken handler',
      fixSummary: 'Added null check guard before invoking jwt.verify',
      diffHash: 'a'.repeat(64),
      prLink: 'https://github.com/devpulse/core/pull/101',
      outcome: 'MITIGATED',
      verificationStatus: 'VERIFIED_RESOLVED',
      resolutionHistory: []
    };

    it('strictly isolates incidents: different repository never matches (returns null)', () => {
      const query: IncidentMemoryQuery = {
        canonicalRepository: 'other-org/other-repo',
        errorSignature: 'TypeError: Cannot read properties of undefined (reading verify)',
        affectedTarget: 'src/auth/jwt.ts',
        minSimilarityScore: 0.1
      };

      const match = evaluateIncidentSimilarity(query, sampleRecord);
      assert.equal(match, null);
    });

    it('matches across repository casing after canonical normalization', () => {
      const query: IncidentMemoryQuery = {
        canonicalRepository: 'DevPulse/Core',
        errorSignature: 'TypeError: Cannot read properties of undefined (reading verify)',
        affectedTarget: 'src/auth/jwt.ts',
        minSimilarityScore: 0.1
      };

      const match = evaluateIncidentSimilarity(query, sampleRecord);
      assert.ok(match !== null);
      assert.equal(match.similarity.matchType, 'EXACT');
    });
  });

  describe('Exact vs. Approximate Match Classification', () => {
    const baseRecord: IncidentMemoryRecord = {
      id: 'INC-2026-002',
      canonicalRepository: 'devpulse/core',
      timestamp: '2026-11-04T11:00:00.000Z',
      category: 'RUNTIME_EXCEPTION',
      errorSignature: 'ConnectionTimeoutError: Failed to connect to Redis on port 6379',
      affectedTarget: 'src/cache/redis.ts',
      rootCause: 'Redis connection pool exhausted',
      fixSummary: 'Increased pool size and added retry backoff',
      diffHash: 'b'.repeat(64),
      prLink: 'https://github.com/devpulse/core/pull/102',
      outcome: 'RESOLVED',
      verificationStatus: 'VERIFIED_RESOLVED',
      resolutionHistory: []
    };

    it('classifies as EXACT when error signature string and target path match exactly after normalization', () => {
      const query: IncidentMemoryQuery = {
        canonicalRepository: 'devpulse/core',
        errorSignature: 'ConnectionTimeoutError: Failed to connect to Redis on port 6379',
        affectedTarget: 'src/cache/redis.ts',
        category: 'RUNTIME_EXCEPTION'
      };

      const match = evaluateIncidentSimilarity(query, baseRecord);
      assert.ok(match !== null);
      assert.equal(match.similarity.matchType, 'EXACT');
      assert.equal(match.similarity.similarityFactors.signatureOverlapScore, 1.0);
      assert.equal(match.similarity.similarityFactors.targetOverlapScore, 1.0);
      assert.equal(match.similarity.similarityFactors.categoryOverlapScore, 1.0);
      assert.equal(match.similarity.overallScore, 0.90);
    });

    it('classifies as APPROXIMATE (NOT EXACT) when tokens match 1.0 but normalized string order differs', () => {
      // Jaccard of tokens is 1.0 because all tokens are identical,
      // but normalized strings differ ("port 6379 on redis..." vs "...redis on port 6379").
      // Exact equality check ensures this is classified as APPROXIMATE, not EXACT!
      const query: IncidentMemoryQuery = {
        canonicalRepository: 'devpulse/core',
        errorSignature: 'ConnectionTimeoutError: On port 6379 failed to connect to Redis',
        affectedTarget: 'src/cache/redis.ts',
        category: 'RUNTIME_EXCEPTION'
      };

      const match = evaluateIncidentSimilarity(query, baseRecord);
      assert.ok(match !== null);
      assert.equal(match.similarity.matchType, 'APPROXIMATE');
      assert.equal(match.similarity.similarityFactors.signatureOverlapScore, 1.0); // token Jaccard is 1.0
      assert.equal(match.similarity.similarityFactors.targetOverlapScore, 1.0);
    });

    it('classifies as APPROXIMATE when target matches but error message has partial token overlap', () => {
      const query: IncidentMemoryQuery = {
        canonicalRepository: 'devpulse/core',
        errorSignature: 'ConnectionTimeoutError: Failed to connect to Redis connection pool',
        affectedTarget: 'src/cache/redis.ts',
        category: 'RUNTIME_EXCEPTION'
      };

      const match = evaluateIncidentSimilarity(query, baseRecord);
      assert.ok(match !== null);
      assert.equal(match.similarity.matchType, 'APPROXIMATE');
      assert.equal(match.similarity.similarityFactors.targetOverlapScore, 1.0);
      assert.ok(match.similarity.similarityFactors.signatureOverlapScore > 0);
      assert.ok(match.similarity.similarityFactors.signatureOverlapScore < 1.0);
    });

    it('NEVER classifies as EXACT when target component is missing from query', () => {
      const query: IncidentMemoryQuery = {
        canonicalRepository: 'devpulse/core',
        errorSignature: 'ConnectionTimeoutError: Failed to connect to Redis on port 6379',
        minSimilarityScore: 0.40
        // affectedTarget omitted
      };

      const match = evaluateIncidentSimilarity(query, baseRecord);
      assert.ok(match !== null);
      assert.equal(match.similarity.matchType, 'APPROXIMATE');
      assert.equal(match.similarity.similarityFactors.targetOverlapScore, 0.0);
      assert.ok(match.similarity.distinguishingDifferences.some(d => d.includes('Target component not provided in query')));
    });

    it('NEVER classifies as EXACT when error signature is missing or empty', () => {
      const recordWithEmptySig: IncidentMemoryRecord = {
        ...baseRecord,
        id: 'INC-2026-EMPTY',
        errorSignature: '   '
      };

      const query: IncidentMemoryQuery = {
        canonicalRepository: 'devpulse/core',
        errorSignature: 'ConnectionTimeoutError: Failed to connect',
        affectedTarget: 'src/cache/redis.ts',
        minSimilarityScore: 0.30
      };

      const match = evaluateIncidentSimilarity(query, recordWithEmptySig);
      assert.ok(match !== null);
      assert.equal(match.similarity.matchType, 'APPROXIMATE');
      assert.equal(match.similarity.similarityFactors.signatureOverlapScore, 0.0);
    });

    it('filters out unrelated incidents whose score falls below minSimilarityScore', () => {
      const query: IncidentMemoryQuery = {
        canonicalRepository: 'devpulse/core',
        errorSignature: 'SyntaxError: Unexpected token < in JSON at position 0',
        affectedTarget: 'src/parser/json.ts',
        minSimilarityScore: 0.60
      };

      const match = evaluateIncidentSimilarity(query, baseRecord);
      assert.equal(match, null);
    });

    it('produces identical scores across repeated runs (deterministic execution)', () => {
      const query: IncidentMemoryQuery = {
        canonicalRepository: 'devpulse/core',
        errorSignature: 'ConnectionTimeoutError: Redis connection failed',
        affectedTarget: 'src/cache/redis.ts'
      };

      const run1 = evaluateIncidentSimilarity(query, baseRecord);
      const run2 = evaluateIncidentSimilarity(query, baseRecord);

      assert.deepEqual(run1, run2);
    });
  });

  describe('Similarity Factor Definitions & Empty Input Consistency', () => {
    const record: IncidentMemoryRecord = {
      id: 'INC-2026-FACTORS',
      canonicalRepository: 'devpulse/core',
      timestamp: '2026-11-04T12:00:00.000Z',
      category: 'BUILD_FAILURE',
      errorSignature: 'BuildError: TS2307 Cannot find module @devpulse/auth',
      affectedTarget: 'src/index.ts',
      rootCause: 'Missing export',
      fixSummary: 'Added index export',
      diffHash: 'f'.repeat(64),
      prLink: 'https://github.com/devpulse/core/pull/200',
      outcome: 'RESOLVED',
      verificationStatus: 'VERIFIED_RESOLVED',
      resolutionHistory: [],
      stackFrames: [
        {
          raw: 'at compile (src/compiler.ts:10:5)',
          file: 'src/compiler.ts',
          functionName: 'compile',
          isProjectSource: true,
          isDependency: false,
          isRuntimeInternal: false
        }
      ]
    };

    it('evaluates all 4 factors independently with documented weights (0.45, 0.35, 0.10, 0.10)', () => {
      const query: IncidentMemoryQuery = {
        canonicalRepository: 'devpulse/core',
        errorSignature: 'BuildError: TS2307 Cannot find module @devpulse/auth',
        affectedTarget: 'src/index.ts',
        category: 'BUILD_FAILURE',
        stackFrames: [
          {
            raw: 'at compile (src/compiler.ts:99:99)',
            file: 'src/compiler.ts',
            functionName: 'compile',
            isProjectSource: true,
            isDependency: false,
            isRuntimeInternal: false
          }
        ]
      };

      const match = evaluateIncidentSimilarity(query, record);
      assert.ok(match !== null);
      assert.equal(match.similarity.similarityFactors.signatureOverlapScore, 1.0);
      assert.equal(match.similarity.similarityFactors.targetOverlapScore, 1.0);
      assert.equal(match.similarity.similarityFactors.categoryOverlapScore, 1.0);
      assert.equal(match.similarity.similarityFactors.frameOverlapScore, 1.0);
      assert.equal(match.similarity.overallScore, 1.0000);
    });

    it('assigns strictly 0.0 to missing factors without throwing or skewing other factors', () => {
      // Query without category, without stackFrames, without target
      const bareQuery: IncidentMemoryQuery = {
        canonicalRepository: 'devpulse/core',
        errorSignature: 'BuildError: TS2307 Cannot find module @devpulse/auth',
        minSimilarityScore: 0.40
      };

      const match = evaluateIncidentSimilarity(bareQuery, record);
      assert.ok(match !== null);
      assert.equal(match.similarity.similarityFactors.signatureOverlapScore, 1.0);
      assert.equal(match.similarity.similarityFactors.targetOverlapScore, 0.0);
      assert.equal(match.similarity.similarityFactors.categoryOverlapScore, 0.0);
      assert.equal(match.similarity.similarityFactors.frameOverlapScore, 0.0);
      // Overall = 1.0 * 0.45 = 0.45
      assert.equal(match.similarity.overallScore, 0.4500);
    });
  });

  describe('Stable Multi-Factor Tie-Breaking', () => {
    it('ranks matches deterministically: score desc -> EXACT before APPROX -> timestamp desc -> id asc', () => {
      const now = Date.now();
      const matchExact: HistoricalIncidentMatch = {
        record: {
          id: 'INC-001',
          canonicalRepository: 'owner/repo',
          timestamp: new Date(now - 1000).toISOString(),
          category: 'RUNTIME_EXCEPTION',
          errorSignature: 'Error A',
          affectedTarget: 'src/a.ts',
          rootCause: 'Cause A',
          fixSummary: 'Fix A',
          diffHash: 'c'.repeat(64),
          prLink: 'pr/1',
          outcome: 'RESOLVED',
          verificationStatus: 'VERIFIED_RESOLVED',
          resolutionHistory: []
        },
        similarity: {
          overallScore: 0.85,
          matchType: 'EXACT',
          similarityFactors: { signatureOverlapScore: 1.0, targetOverlapScore: 1.0, categoryOverlapScore: 0, frameOverlapScore: 0 },
          reasons: [],
          distinguishingDifferences: []
        },
        verificationStatus: 'VERIFIED_RESOLVED',
        relevanceExplanation: ''
      };

      const matchApproxSameScore: HistoricalIncidentMatch = {
        ...matchExact,
        record: { ...matchExact.record, id: 'INC-002' },
        similarity: {
          ...matchExact.similarity,
          matchType: 'APPROXIMATE'
        }
      };

      const matchHigherScoreApprox: HistoricalIncidentMatch = {
        ...matchExact,
        record: { ...matchExact.record, id: 'INC-003' },
        similarity: {
          ...matchExact.similarity,
          overallScore: 0.95,
          matchType: 'APPROXIMATE'
        }
      };

      const matchExactOlder: HistoricalIncidentMatch = {
        ...matchExact,
        record: {
          ...matchExact.record,
          id: 'INC-004',
          timestamp: new Date(now - 50000).toISOString()
        }
      };

      const matchExactSameTimeHigherId: HistoricalIncidentMatch = {
        ...matchExact,
        record: {
          ...matchExact.record,
          id: 'INC-999'
        }
      };

      // Ranked order expected:
      // 1. matchHigherScoreApprox (score 0.95)
      // 2. matchExact (score 0.85, EXACT, recent timestamp, id INC-001)
      // 3. matchExactSameTimeHigherId (score 0.85, EXACT, same timestamp as INC-001, id INC-999)
      // 4. matchExactOlder (score 0.85, EXACT, older timestamp, id INC-004)
      // 5. matchApproxSameScore (score 0.85, APPROXIMATE)
      const input = [
        matchApproxSameScore,
        matchExactOlder,
        matchExactSameTimeHigherId,
        matchHigherScoreApprox,
        matchExact
      ];

      const ranked = rankHistoricalMatches(input);
      assert.equal(ranked[0]?.record.id, 'INC-003');
      assert.equal(ranked[1]?.record.id, 'INC-001');
      assert.equal(ranked[2]?.record.id, 'INC-999');
      assert.equal(ranked[3]?.record.id, 'INC-004');
      assert.equal(ranked[4]?.record.id, 'INC-002');
    });
  });

  describe('Resolution Verification Status Schema', () => {
    it('validates full IncidentMemoryRecord schema with verification status & resolution history', () => {
      const record = {
        id: 'INC-2026-900',
        canonicalRepository: 'my-org/my-service',
        timestamp: new Date().toISOString(),
        category: 'BUILD_FAILURE',
        errorSignature: 'error TS2322: Type string is not assignable to type number',
        affectedTarget: 'src/types/config.ts',
        rootCause: 'Type definition changed without updating downstream parser',
        fixSummary: 'Updated config parser return type',
        diffHash: 'd'.repeat(64),
        prLink: 'https://github.com/my-org/my-service/pull/45',
        outcome: 'RESOLVED',
        verificationStatus: 'VERIFIED_RESOLVED',
        resolutionHistory: [
          {
            id: 'RH-1',
            toStatus: 'UNVERIFIED_PROPOSAL',
            timestamp: new Date(Date.now() - 3600000).toISOString(),
            evidence: 'Initial patch suggested in investigation report'
          },
          {
            id: 'RH-2',
            fromStatus: 'UNVERIFIED_PROPOSAL',
            toStatus: 'VERIFIED_RESOLVED',
            timestamp: new Date().toISOString(),
            evidence: 'PR #45 merged into main and all CI suites passed without regression',
            actor: {
              type: 'HUMAN',
              id: 'lead-dev',
              name: 'Lead Developer'
            }
          }
        ]
      };

      const parsed = IncidentMemoryRecordSchema.parse(record);
      assert.equal(parsed.verificationStatus, 'VERIFIED_RESOLVED');
      assert.equal(parsed.resolutionHistory.length, 2);
    });
  });
});
