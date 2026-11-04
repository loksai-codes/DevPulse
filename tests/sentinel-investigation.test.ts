import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseStackTrace } from '../src/sentinel/analyzer/stack-trace-parser.js';
import { classifyIncident } from '../src/sentinel/analyzer/incident-classifier.js';
import { diagnoseIncident } from '../src/sentinel/analyzer/root-cause-engine.js';

describe('Sentinel Intelligence Engine — Sub-Stage 4.1 Diagnostic Verification', () => {

  // =========================================================================
  // 1. EVIDENCE PROVENANCE & CULPRIT CANDIDACY
  // =========================================================================
  describe('1. Evidence Provenance & Candidate Culprit Location', () => {
    const rawTrace = [
      "TypeError: Cannot read properties of undefined (reading 'expiresAt')",
      '    at SessionManager.validateToken (src/auth/session.ts:42:19)',
      '    at handleAuth (src/middleware/auth.ts:15:5)',
      '    at Layer.handle (node_modules/express/lib/router/layer.js:95:5)'
    ].join('\n');

    it('ensures every finding has traceable evidence source, confidence, and uncertainty reasons', () => {
      const parsedTrace = parseStackTrace(rawTrace);
      const classification = classifyIncident(rawTrace, parsedTrace);
      const diagnosis = diagnoseIncident(rawTrace, classification, parsedTrace);

      assert.ok(diagnosis.findings.length >= 2);
      for (const finding of diagnosis.findings) {
        assert.ok(finding.id, 'Finding must have an id');
        assert.ok(finding.evidenceSource, 'Finding must have a traceable evidence source');
        assert.ok(['CONFIRMED_FACT', 'HYPOTHESIS', 'RECOMMENDATION'].includes(finding.type));
        assert.ok(finding.confidence >= 0 && finding.confidence <= 1);
        assert.ok(Array.isArray(finding.uncertaintyReasons), 'Must track uncertainty reasons');
      }
    });

    it('marks first application frame strictly as candidateCulpritFrame, not a confirmed root cause', () => {
      const parsedTrace = parseStackTrace(rawTrace);
      const classification = classifyIncident(rawTrace, parsedTrace);
      const diagnosis = diagnoseIncident(rawTrace, classification, parsedTrace);

      // Candidate culprit frame points to first project source
      assert.ok(diagnosis.candidateCulpritFrame);
      assert.equal(diagnosis.candidateCulpritFrame?.file, 'src/auth/session.ts');
      assert.equal(diagnosis.candidateCulpritFrame?.line, 42);
      assert.equal(diagnosis.candidateCulpritFrame?.isProjectSource, true);

      // Fact finding confirms execution point
      const executionFact = diagnosis.findings.find((f) => f.id === 'fact_execution_location');
      assert.ok(executionFact);
      assert.equal(executionFact?.type, 'CONFIRMED_FACT');
      assert.match(executionFact?.description!, /Execution halted in project source at candidate location/);

      // Root cause finding is strictly a HYPOTHESIS
      const rootCauseHypothesis = diagnosis.findings.find((f) => f.type === 'HYPOTHESIS');
      assert.ok(rootCauseHypothesis);
      assert.match(rootCauseHypothesis?.description!, /Uncaught null or undefined dereference/);
      assert.ok(rootCauseHypothesis?.uncertaintyReasons.length! > 0);
    });
  });

  // =========================================================================
  // 2. EVIDENCE COMPLETENESS TAXONOMY
  // =========================================================================
  describe('2. Evidence Completeness Taxonomy (COMPLETE, PARTIAL, INSUFFICIENT)', () => {
    it('classifies full trace with project frames as COMPLETE', () => {
      const log = [
        'ReferenceError: config is not defined',
        '    at initializeServer (src/server.ts:18:3)',
        '    at main (src/index.ts:5:1)'
      ].join('\n');

      const parsed = parseStackTrace(log);
      const classification = classifyIncident(log, parsed);
      const diagnosis = diagnoseIncident(log, classification, parsed);

      assert.equal(classification.evidenceCompleteness, 'COMPLETE');
      assert.equal(classification.category, 'RUNTIME_EXCEPTION');
      assert.ok(diagnosis.diagnosticConfidence >= 0.85);
      assert.equal(diagnosis.limitations.length, 0);
    });

    it('classifies trace with missing project source or lines as PARTIAL', () => {
      const log = [
        'TypeError: boom',
        '    at Layer.handle (node_modules/express/lib/router/layer.js:95:5)',
        '    at processTicksAndRejections (node:internal/process/task_queues:95:5)'
      ].join('\n');

      const parsed = parseStackTrace(log);
      const classification = classifyIncident(log, parsed);
      const diagnosis = diagnoseIncident(log, classification, parsed);

      assert.equal(classification.evidenceCompleteness, 'PARTIAL');
      assert.ok(diagnosis.diagnosticConfidence < 0.7);
      assert.ok(diagnosis.limitations.some((l) => l.includes('third-party dependencies')));
      assert.ok(diagnosis.unresolvedQuestions.length > 0);
    });

    it('classifies vague log lines without error type or stack as INSUFFICIENT', () => {
      const log = 'User reported that the page failed to load after submitting form';

      const parsed = parseStackTrace(log);
      const classification = classifyIncident(log, parsed);
      const diagnosis = diagnoseIncident(log, classification, parsed);

      assert.equal(classification.evidenceCompleteness, 'INSUFFICIENT');
      assert.equal(classification.category, 'UNRECOGNIZED_ERROR');
      assert.ok(diagnosis.diagnosticConfidence <= 0.25);
      assert.ok(diagnosis.limitations.some((l) => l.includes('lacks structured exception headers')));
      assert.ok(diagnosis.unresolvedQuestions.length > 0);
    });
  });

  // =========================================================================
  // 3. MALFORMED LOGS & MISLEADING STACK TRACES
  // =========================================================================
  describe('3. Malformed Logs & Misleading Stack Traces', () => {
    it('handles truncated stack traces without throwing', () => {
      const truncated = [
        'TypeError: Cannot read properties of null',
        '    at Object.run (src/worker.ts:10', // Truncated mid-line!
        '    at'                               // Incomplete token!
      ].join('\n');

      const parsed = parseStackTrace(truncated);
      const classification = classifyIncident(truncated, parsed);
      const diagnosis = diagnoseIncident(truncated, classification, parsed);

      assert.equal(parsed.errorType, 'TypeError');
      assert.ok(diagnosis.findings.length > 0);
      assert.doesNotThrow(() => JSON.stringify(diagnosis));
    });

    it('resolves misleading stack traces where error is thrown in node_modules but called from project code', () => {
      const traceWithDependencyCulprit = [
        'TypeError: path must be a string',
        '    at validatePath (node_modules/fs-extra/lib/index.js:12:9)',
        '    at Object.readFile (node_modules/fs-extra/lib/read.js:45:3)',
        '    at ConfigLoader.load (src/config/loader.ts:31:14)',
        '    at startApp (src/index.ts:10:5)'
      ].join('\n');

      const parsed = parseStackTrace(traceWithDependencyCulprit);
      const classification = classifyIncident(traceWithDependencyCulprit, parsed);
      const diagnosis = diagnoseIncident(traceWithDependencyCulprit, classification, parsed);

      // Frame 0 is node_modules, but candidateCulpritFrame should skip node_modules to find src/config/loader.ts
      assert.equal(parsed.hasApplicationFrame, true);
      assert.equal(diagnosis.candidateCulpritFrame?.file, 'src/config/loader.ts');
      assert.equal(diagnosis.candidateCulpritFrame?.line, 31);
      assert.equal(diagnosis.candidateCulpritFrame?.isProjectSource, true);
    });

    it('parses TypeScript build and syntax compiler errors', () => {
      const tsOutput = 'src/types/auth.ts:14:22 - error TS2322: Type "string | null" is not assignable to type "string".';

      const parsed = parseStackTrace(tsOutput);
      const classification = classifyIncident(tsOutput, parsed);
      const diagnosis = diagnoseIncident(tsOutput, classification, parsed);

      assert.equal(classification.category, 'BUILD_FAILURE');
      assert.equal(parsed.errorType, 'TS2322');
      assert.equal(diagnosis.candidateCulpritFrame?.file, 'src/types/auth.ts');
      assert.equal(diagnosis.candidateCulpritFrame?.line, 14);
      assert.equal(diagnosis.candidateCulpritFrame?.column, 22);
    });

    it('parses test assertion failures into TEST_FAILURE category', () => {
      const testLog = [
        'AssertionError [ERR_ASSERTION]: Expected values to be strictly equal:',
        'false !== true',
        '    at TestContext.<anonymous> (tests/unit/login.test.ts:45:12)',
        '    at Test.run (node:internal/test_runner/test:1106:25)'
      ].join('\n');

      const parsed = parseStackTrace(testLog);
      const classification = classifyIncident(testLog, parsed);
      const diagnosis = diagnoseIncident(testLog, classification, parsed);

      assert.equal(classification.category, 'TEST_FAILURE');
      assert.equal(parsed.errorType, 'AssertionError');
      assert.equal(diagnosis.candidateCulpritFrame?.file, 'tests/unit/login.test.ts');
    });
  });

  // =========================================================================
  // 4. DECOUPLED CONFIDENCE METRIC
  // =========================================================================
  describe('4. Decoupled Diagnostic Confidence (No Risk Calculations in Sub-Stage 4.1)', () => {
    it('proves diagnosticConfidence is calculated strictly from evidence completeness, independent of severity', () => {
      // 1. Minor typo with complete evidence -> High diagnostic confidence
      const minorTypo = [
        'ReferenceError: foo is not defined',
        '    at displayBanner (src/views/banner.ts:10:5)'
      ].join('\n');
      const minorParsed = parseStackTrace(minorTypo);
      const minorClass = classifyIncident(minorTypo, minorParsed);
      const minorDiagnosis = diagnoseIncident(minorTypo, minorClass, minorParsed);

      assert.equal(minorDiagnosis.evidenceCompleteness, 'COMPLETE');
      assert.ok(minorDiagnosis.diagnosticConfidence >= 0.85);

      // 2. Catastrophic alert with vague text -> Low diagnostic confidence
      const criticalOutage = 'CRITICAL PagerDuty Alert: Entire payment cluster is down and returning 500s';
      const outageParsed = parseStackTrace(criticalOutage);
      const outageClass = classifyIncident(criticalOutage, outageParsed);
      const outageDiagnosis = diagnoseIncident(criticalOutage, outageClass, outageParsed);

      assert.equal(outageDiagnosis.evidenceCompleteness, 'INSUFFICIENT');
      assert.ok(outageDiagnosis.diagnosticConfidence <= 0.25);
    });
  });
});

