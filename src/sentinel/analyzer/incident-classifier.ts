import {
  IncidentCategory,
  EvidenceCompleteness,
  IncidentClassification,
  ParsedStackTrace
} from '../types.js';

/**
 * Classifies an incoming incident into structured categories and evaluates
 * evidence completeness per strict taxonomy rules.
 */
export function classifyIncident(
  rawText: string,
  parsedTrace: ParsedStackTrace
): IncidentClassification {
  const trimmed = rawText.trim();
  const lower = trimmed.toLowerCase();

  // 1. Determine Incident Category
  let category: IncidentCategory = 'UNRECOGNIZED_ERROR';

  if (
    parsedTrace.errorType?.startsWith('TS') ||
    lower.includes('build failed') ||
    lower.includes('compilation error') ||
    lower.includes('syntaxerror')
  ) {
    category = 'BUILD_FAILURE';
  } else if (
    parsedTrace.errorType === 'AssertionError' ||
    lower.includes('err_assertion') ||
    lower.includes('test failed') ||
    lower.includes('failing test')
  ) {
    category = 'TEST_FAILURE';
  } else if (
    lower.includes('pagerduty') ||
    lower.includes('datadog alert') ||
    lower.includes('production alert') ||
    lower.includes('critical alert') ||
    lower.includes('service unavailable') ||
    lower.includes('cluster down') ||
    lower.includes('5xx rate') ||
    lower.includes('latency spike') ||
    lower.includes('high memory alert')
  ) {
    category = 'PRODUCTION_ALERT';
  } else if (
    parsedTrace.errorType ||
    lower.includes('typeerror') ||
    lower.includes('referenceerror') ||
    lower.includes('uncaught exception') ||
    lower.includes('unhandledrejection') ||
    lower.includes('runtime error')
  ) {
    category = 'RUNTIME_EXCEPTION';
  }

  // 2. Determine Evidence Completeness
  // COMPLETE: Both error header (type/message) AND at least one project source frame with line number.
  // PARTIAL: Error type/message present, but missing project source frames or line numbers.
  // INSUFFICIENT: Missing error type and missing usable file location.
  let evidenceCompleteness: EvidenceCompleteness = 'INSUFFICIENT';

  const hasErrorHeader = Boolean(parsedTrace.errorType || parsedTrace.errorMessage);
  const hasProjectSourceFrame = Boolean(
    parsedTrace.candidateCulpritFrame &&
    parsedTrace.candidateCulpritFrame.isProjectSource &&
    parsedTrace.candidateCulpritFrame.line !== undefined
  );

  if (hasErrorHeader && hasProjectSourceFrame) {
    evidenceCompleteness = 'COMPLETE';
  } else if (hasErrorHeader || parsedTrace.frames.length > 0) {
    evidenceCompleteness = 'PARTIAL';
  } else {
    evidenceCompleteness = 'INSUFFICIENT';
  }

  const summary = [
    `Category: ${category}`,
    `Completeness: ${evidenceCompleteness}`,
    parsedTrace.errorType ? `Type: ${parsedTrace.errorType}` : null,
    parsedTrace.candidateCulpritFrame
      ? `Candidate Culprit: ${parsedTrace.candidateCulpritFrame.file}${parsedTrace.candidateCulpritFrame.line ? `:${parsedTrace.candidateCulpritFrame.line}` : ''}`
      : null
  ]
    .filter(Boolean)
    .join(' | ');

  return {
    category,
    evidenceCompleteness,
    summary,
    extractedErrorType: parsedTrace.errorType,
    extractedMessage: parsedTrace.errorMessage
  };
}

