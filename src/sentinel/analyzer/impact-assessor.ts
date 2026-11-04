import {
  EvidenceBasedImpact,
  BlastRadiusType,
  ParsedStackTrace,
  IncidentClassification
} from '../types.js';

// Regex to discover explicit service identifiers in logs: "service=auth-api", "service: payments", "[auth-service]"
const SERVICE_TOKEN_REGEX = /(?:service[=:\s]+|app[=:\s]+|cluster[=:\s]+|\[)([a-zA-Z0-9_\-]+(?:-service|-api|-worker|-gateway|service|worker|api))(?:\b|\])/i;

// Regex to identify explicit failure observations in logs: "500 Internal Server Error", "connection refused", "timeout after 5000ms"
const OBSERVED_FAILURE_REGEX = /(?:5\d\d(?:\s+(?:Internal Server Error|Service Unavailable|Bad Gateway|Gateway Timeout))?|connection\s+refused|connection\s+reset|timeout\s+after\s+\d+m?s|out\s+of\s+memory|crash\s+loop)/i;

/**
 * Assesses operational and component impact strictly grounded in verifiable log evidence.
 * Never invents user counts, financial metrics, or uncorroborated service outages.
 */
export function assessImpact(
  rawText: string,
  parsedTrace: ParsedStackTrace,
  classification: IncidentClassification
): EvidenceBasedImpact {
  const affectedComponents: string[] = [];
  const affectedServices: string[] = [];
  const observedFailures: string[] = [];
  const unverifiedAssumptions: string[] = [];

  // 1. Identify Affected Components from Parsed Culprit Frame
  if (parsedTrace.candidateCulpritFrame?.file) {
    affectedComponents.push(parsedTrace.candidateCulpritFrame.file);
  } else {
    // Exact UNKNOWN token per requirement: do not insert sentences into affectedComponents
    affectedComponents.push('UNKNOWN');
  }

  // 2. Identify Corroborated Services from Explicit Evidence Only
  const serviceMatch = rawText.match(SERVICE_TOKEN_REGEX);
  if (serviceMatch && serviceMatch[1]) {
    affectedServices.push(serviceMatch[1].trim());
  }

  // 3. Identify Observed Failures from Evidence
  const failureMatch = rawText.match(OBSERVED_FAILURE_REGEX);
  if (failureMatch) {
    observedFailures.push(failureMatch[0].trim());
  } else if (parsedTrace.errorType || parsedTrace.errorMessage) {
    observedFailures.push(`${parsedTrace.errorType || 'Error'}: ${parsedTrace.errorMessage || 'Failure'}`);
  } else {
    observedFailures.push('Unspecified failure');
  }

  // 4. Classify Blast Radius
  // KNOWN: Explicit service corroborated AND specific failure confirmed in log.
  // ESTIMATED: Culprit file identified, but downstream service reach is uncorroborated.
  // UNKNOWN: Insufficient evidence or no culprit file.
  let blastRadiusType: BlastRadiusType = 'UNKNOWN';
  let evidenceSummary = '';

  if (affectedComponents[0] === 'UNKNOWN' || classification.evidenceCompleteness === 'INSUFFICIENT') {
    blastRadiusType = 'UNKNOWN';
    evidenceSummary = 'Evidence is insufficient to determine blast radius or candidate component';
    unverifiedAssumptions.push('No verifiable file paths or stack frames present in log');
  } else if (affectedServices.length > 0 && observedFailures.length > 0 && parsedTrace.hasApplicationFrame) {
    blastRadiusType = 'KNOWN';
    evidenceSummary = `Confirmed component '${affectedComponents[0]}' in service '${affectedServices[0]}' exhibiting '${observedFailures[0]}'`;
    unverifiedAssumptions.push('Downstream ripple effects on secondary consumers require live tracing');
  } else {
    blastRadiusType = 'ESTIMATED';
    evidenceSummary = `Candidate component '${affectedComponents[0]}' derived from stack frame; broader service impact uncorroborated`;
    unverifiedAssumptions.push('Multiple stack frames do not confirm downstream service degradation');
    if (affectedServices.length === 0) {
      unverifiedAssumptions.push('No explicit service name corroborated in incident payload');
    }
  }

  return {
    classification: blastRadiusType,
    affectedComponents,
    affectedServices,
    observedFailures,
    evidenceSummary,
    unverifiedAssumptions
  };
}
