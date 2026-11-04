import {
  Finding,
  InvestigationDiagnosis,
  ParsedStackTrace,
  IncidentClassification
} from '../types.js';

/**
 * Evidence-Grounded Root Cause Engine.
 * Formulates findings strictly with traceable evidence sources, distinguishes
 * confirmed facts from hypotheses, and computes diagnostic confidence independently
 * of incident risk.
 */
export function diagnoseIncident(
  rawText: string,
  classification: IncidentClassification,
  parsedTrace: ParsedStackTrace
): InvestigationDiagnosis {
  const findings: Finding[] = [];
  const confirmedFacts: string[] = [];
  const hypotheses: string[] = [];
  const unresolvedQuestions: string[] = [];
  const limitations: string[] = [];

  // 1. Evaluate Evidence Completeness & Limitations
  if (classification.evidenceCompleteness === 'INSUFFICIENT') {
    limitations.push('Log input lacks structured exception headers and valid file/line references');
    unresolvedQuestions.push('What specific runtime operation or component threw this error?');
  } else if (classification.evidenceCompleteness === 'PARTIAL') {
    if (!parsedTrace.hasApplicationFrame) {
      limitations.push('Stack trace contains only third-party dependencies or runtime internals with no application source frames');
      unresolvedQuestions.push('Which first-party application caller invoked the failing dependency?');
    }
    if (!parsedTrace.candidateCulpritFrame?.line) {
      limitations.push('Stack frame identifies a target file but lacks exact line number');
    }
  }

  // 2. Fact Finding: Error Signature
  if (parsedTrace.errorType || parsedTrace.errorMessage) {
    const errorDesc = `${parsedTrace.errorType ?? 'Error'}: ${parsedTrace.errorMessage ?? 'Unspecified error'}`;
    const evidenceSource = rawText.split('\n')[0]?.trim() || rawText.slice(0, 100).trim();

    findings.push({
      id: 'fact_error_signature',
      type: 'CONFIRMED_FACT',
      description: `Observed error signature: ${errorDesc}`,
      evidenceSource,
      confidence: 1.0,
      uncertaintyReasons: []
    });
    confirmedFacts.push(`Error signature verified: ${errorDesc}`);
  } else {
    limitations.push('Could not deterministically extract standard exception type from input text');
  }

  // 3. Fact Finding: Candidate Culprit Frame (Execution Location)
  if (parsedTrace.candidateCulpritFrame) {
    const frame = parsedTrace.candidateCulpritFrame;
    const loc = `${frame.file}${frame.line ? `:${frame.line}` : ''}${frame.column ? `:${frame.column}` : ''}`;
    const desc = frame.isProjectSource
      ? `Execution halted in project source at candidate location ${loc}${frame.functionName ? ` in ${frame.functionName}` : ''}`
      : `Execution halted inside external dependency or runtime at ${loc}`;

    findings.push({
      id: 'fact_execution_location',
      type: 'CONFIRMED_FACT',
      description: desc,
      evidenceSource: frame.raw,
      file: frame.file,
      line: frame.line,
      column: frame.column,
      confidence: frame.line ? 0.95 : 0.7,
      uncertaintyReasons: frame.isProjectSource
        ? ['Candidate culprit frame indicates point of failure, but root-cause defect may reside in caller data or state']
        : ['Failure occurred in external dependency; application caller context is missing']
    });

    confirmedFacts.push(desc);
  } else {
    limitations.push('No stack frames or file references could be extracted from incident input');
  }

  // 4. Hypothesis Finding: Root Cause Deduction
  const hypothesisDeduction = deduceRootCauseHypothesis(parsedTrace, classification);
  if (hypothesisDeduction) {
    findings.push(hypothesisDeduction);
    hypotheses.push(hypothesisDeduction.description);
  } else {
    hypotheses.push('Root cause cannot be hypothesized without verifiable error tokens');
    unresolvedQuestions.push('Can full stack trace or caller payload be provided?');
  }

  // 5. Diagnostic Confidence Calculation (Decoupled from Risk)
  // Reflects strictly evidence provenance and clarity:
  // - COMPLETE evidence: 0.85 - 0.95
  // - PARTIAL evidence: 0.40 - 0.65
  // - INSUFFICIENT evidence: 0.10 - 0.25
  let diagnosticConfidence = 0.2;
  if (classification.evidenceCompleteness === 'COMPLETE') {
    diagnosticConfidence = parsedTrace.hasApplicationFrame ? 0.9 : 0.75;
  } else if (classification.evidenceCompleteness === 'PARTIAL') {
    diagnosticConfidence = parsedTrace.candidateCulpritFrame ? 0.55 : 0.4;
  } else {
    diagnosticConfidence = 0.15;
  }

  return {
    incidentCategory: classification.category,
    evidenceCompleteness: classification.evidenceCompleteness,
    rawErrorSignature: rawText.slice(0, 160).trim(),
    errorType: parsedTrace.errorType,
    errorMessage: parsedTrace.errorMessage,
    candidateCulpritFrame: parsedTrace.candidateCulpritFrame,
    stackFrames: parsedTrace.frames,
    findings,
    confirmedFacts,
    hypotheses,
    diagnosticConfidence,
    unresolvedQuestions,
    limitations
  };
}

function deduceRootCauseHypothesis(
  parsedTrace: ParsedStackTrace,
  classification: IncidentClassification
): Finding | null {
  const msg = parsedTrace.errorMessage?.toLowerCase() || '';
  const errType = parsedTrace.errorType || '';
  const frame = parsedTrace.candidateCulpritFrame;

  if (errType === 'TypeError' && (msg.includes('cannot read propert') || msg.includes('is undefined') || msg.includes('is null'))) {
    const propMatch = msg.match(/reading '([a-zA-Z0-9_$]+)'/);
    const prop = propMatch ? `'${propMatch[1]}'` : 'a property';
    const loc = frame?.file ? `in ${frame.file}${frame.line ? `:${frame.line}` : ''}` : 'at execution point';

    return {
      id: 'hyp_null_dereference',
      type: 'HYPOTHESIS',
      description: `Uncaught null or undefined dereference accessing ${prop} ${loc}`,
      evidenceSource: parsedTrace.errorMessage || 'TypeError thrown on property access',
      file: frame?.file,
      line: frame?.line,
      confidence: 0.85,
      uncertaintyReasons: [
        'Root cause could be unhandled asynchronous resolution, missing default payload, or unexpected upstream API response'
      ]
    };
  }

  if (errType.startsWith('TS') || classification.category === 'BUILD_FAILURE') {
    return {
      id: 'hyp_type_mismatch',
      type: 'HYPOTHESIS',
      description: `Type system or compiler constraint violation: ${parsedTrace.errorMessage || 'compilation error'}`,
      evidenceSource: parsedTrace.errorMessage || 'Compiler error output',
      file: frame?.file,
      line: frame?.line,
      confidence: 0.9,
      uncertaintyReasons: ['Type mismatch may stem from changed dependency definitions or mismatched return type']
    };
  }

  if (errType === 'AssertionError' || classification.category === 'TEST_FAILURE') {
    return {
      id: 'hyp_assertion_failure',
      type: 'HYPOTHESIS',
      description: `Behavioral regression or contract break: test assertion failed: ${parsedTrace.errorMessage || 'assertion failed'}`,
      evidenceSource: parsedTrace.errorMessage || 'Assertion failure output',
      file: frame?.file,
      line: frame?.line,
      confidence: 0.85,
      uncertaintyReasons: ['Failure may indicate actual bug in tested code or outdated test expectation']
    };
  }

  if (frame) {
    return {
      id: 'hyp_generic_execution_failure',
      type: 'HYPOTHESIS',
      description: `Execution failure in ${frame.file}${frame.line ? ` at line ${frame.line}` : ''}`,
      evidenceSource: frame.raw,
      file: frame.file,
      line: frame.line,
      confidence: 0.6,
      uncertaintyReasons: ['Limited error details prevent specific root-cause deduction beyond failure location']
    };
  }

  return null;
}

