import {
  IncidentMemoryQuery,
  IncidentMemoryRecord,
  HistoricalIncidentMatch,
  HistoricalMatchExplanation,
  normalizeCanonicalRepository
} from './types.js';
import {
  normalizeErrorSignature,
  normalizeTargetComponent,
  normalizeStackFrames
} from './normalization.js';

// Weight configuration for deterministic multi-factor similarity
export const SIMILARITY_WEIGHTS = {
  SIGNATURE_OVERLAP: 0.45,
  TARGET_OVERLAP: 0.35,
  CATEGORY_OVERLAP: 0.10,
  FRAME_OVERLAP: 0.10
} as const;

/**
 * Calculates deterministic Jaccard similarity coefficient between two string sets:
 * J(A, B) = |A ∩ B| / |A ∪ B|
 * Returns 0.0000 if either set is empty (missing info is never treated as a match).
 * Results are rounded to 4 decimal places.
 */
export function calculateJaccardSimilarity(setA: Set<string>, setB: Set<string>): number {
  if (setA.size === 0 || setB.size === 0) {
    return 0.0;
  }

  let intersectionCount = 0;
  for (const item of setA) {
    if (setB.has(item)) {
      intersectionCount++;
    }
  }

  const unionCount = setA.size + setB.size - intersectionCount;
  if (unionCount === 0) {
    return 0.0;
  }

  return Math.round((intersectionCount / unionCount) * 10000) / 10000;
}

/**
 * Evaluates similarity between an incident query and a historical memory record.
 *
 * Deterministic Similarity Factor Calculations:
 *
 * 1. Error Signature Overlap (Weight 0.45):
 *    - Strips hex addresses, timestamps, PIDs/threads, UUIDs, and line/column numbers.
 *    - If both normalized signatures are non-empty:
 *        - If normalizedText is identical: score = 1.0000.
 *        - Otherwise: score = calculateJaccardSimilarity(queryTokens, recordTokens).
 *    - If either normalized signature is empty: score = 0.0000.
 *
 * 2. Target Component Overlap (Weight 0.35):
 *    - Standardizes directory slashes to '/', strips leading './', and lowercases.
 *    - If both normalized paths are non-empty:
 *        - If normalizedPath is identical: score = 1.0000.
 *        - Otherwise: score = calculateJaccardSimilarity(queryTargetTokens, recordTargetTokens).
 *    - If either normalized path is empty: score = 0.0000.
 *
 * 3. Incident Category Match (Weight 0.10):
 *    - If both query.category and record.category are present and non-empty:
 *        - If query.category === record.category: score = 1.0000.
 *        - Otherwise: score = 0.0000.
 *    - If either is missing or undefined: score = 0.0000.
 *
 * 4. Stack Frame Overlap (Weight 0.10):
 *    - Strips volatile line/column coordinates, extracting [filePath]:[functionName].
 *    - If both query.stackFrames and record.stackFrames are present and non-empty:
 *        - Let J_desc = calculateJaccardSimilarity(queryDescriptors, recordDescriptors).
 *        - If J_desc > 0: score = J_desc.
 *        - Otherwise: score = round_4(calculateJaccardSimilarity(queryTokens, recordTokens) * 0.5).
 *    - If either is missing or empty array: score = 0.0000.
 *
 * Exact Match Rule:
 *    - Strictly requires exact string equality of non-empty normalizedText AND
 *      exact string equality of non-empty normalizedPath.
 *    - Never relies solely on Jaccard token scores or missing data.
 *
 * Returns null if repository isolation fails or overall score < minSimilarityScore.
 */
export function evaluateIncidentSimilarity(
  query: IncidentMemoryQuery,
  record: IncidentMemoryRecord
): HistoricalIncidentMatch | null {
  // 1. Strict repository isolation using normalized repository identifiers
  let queryRepo: string;
  let recordRepo: string;
  try {
    queryRepo = normalizeCanonicalRepository(query.canonicalRepository);
    recordRepo = normalizeCanonicalRepository(record.canonicalRepository);
  } catch {
    // If either fails validation, reject immediately
    return null;
  }

  if (queryRepo !== recordRepo) {
    return null;
  }

  const reasons: string[] = [];
  const distinguishingDifferences: string[] = [];

  // 2. Factor 1: Error Signature Overlap (Weight 0.45)
  const normQuerySig = normalizeErrorSignature(query.errorSignature);
  const normRecordSig = normalizeErrorSignature(record.errorSignature);

  let signatureOverlapScore = 0.0;
  if (normQuerySig.normalizedText.length > 0 && normRecordSig.normalizedText.length > 0) {
    if (normQuerySig.normalizedText === normRecordSig.normalizedText) {
      signatureOverlapScore = 1.0;
      reasons.push('Error signatures match exactly after normalization');
    } else {
      signatureOverlapScore = calculateJaccardSimilarity(normQuerySig.tokens, normRecordSig.tokens);
      if (signatureOverlapScore > 0) {
        reasons.push(`Error signatures share token overlap (Jaccard: ${signatureOverlapScore.toFixed(4)})`);
      } else {
        distinguishingDifferences.push('Error signatures have no overlapping tokens');
      }
    }
  } else {
    distinguishingDifferences.push('Missing error signature in query or record');
  }

  if (normQuerySig.errorType && normRecordSig.errorType && normQuerySig.errorType !== normRecordSig.errorType) {
    distinguishingDifferences.push(
      `Different error types: query has '${normQuerySig.errorType}', record has '${normRecordSig.errorType}'`
    );
  }

  // 3. Factor 2: Target Component Overlap (Weight 0.35)
  let targetOverlapScore = 0.0;
  const normQueryTarget = normalizeTargetComponent(query.affectedTarget);
  const normRecordTarget = normalizeTargetComponent(record.affectedTarget);

  if (normQueryTarget.normalizedPath.length > 0 && normRecordTarget.normalizedPath.length > 0) {
    if (normQueryTarget.normalizedPath === normRecordTarget.normalizedPath) {
      targetOverlapScore = 1.0;
      reasons.push(`Target component matches exactly: '${normQueryTarget.normalizedPath}'`);
    } else {
      targetOverlapScore = calculateJaccardSimilarity(normQueryTarget.tokens, normRecordTarget.tokens);
      if (targetOverlapScore > 0) {
        reasons.push(`Target components share path segments (Jaccard: ${targetOverlapScore.toFixed(4)})`);
      } else {
        distinguishingDifferences.push(
          `Distinct targets: query targeted '${normQueryTarget.normalizedPath}', record targeted '${normRecordTarget.normalizedPath}'`
        );
      }
    }
  } else {
    if (!normQueryTarget.normalizedPath) {
      distinguishingDifferences.push('Target component not provided in query');
    }
    if (!normRecordTarget.normalizedPath) {
      distinguishingDifferences.push('Target component not present in historical record');
    }
  }

  // 4. Factor 3: Incident Category Match (Weight 0.10)
  let categoryOverlapScore = 0.0;
  if (query.category && record.category) {
    if (query.category === record.category) {
      categoryOverlapScore = 1.0;
      reasons.push(`Incident category match: '${query.category}'`);
    } else {
      categoryOverlapScore = 0.0;
      distinguishingDifferences.push(
        `Category mismatch: query is '${query.category}', record is '${record.category}'`
      );
    }
  } else {
    if (!query.category) {
      distinguishingDifferences.push('Category not provided in query');
    }
  }

  // 5. Factor 4: Stack Frame Overlap (Weight 0.10)
  let frameOverlapScore = 0.0;
  if (
    query.stackFrames &&
    query.stackFrames.length > 0 &&
    record.stackFrames &&
    record.stackFrames.length > 0
  ) {
    const normQueryFrames = normalizeStackFrames(query.stackFrames);
    const normRecordFrames = normalizeStackFrames(record.stackFrames);

    const descSetA = new Set(normQueryFrames.frameDescriptors);
    const descSetB = new Set(normRecordFrames.frameDescriptors);

    const descJaccard = calculateJaccardSimilarity(descSetA, descSetB);
    if (descJaccard > 0) {
      frameOverlapScore = descJaccard;
      reasons.push(`Stack frames match location signatures (Jaccard: ${descJaccard.toFixed(4)})`);
    } else {
      // Fallback to token overlap across frames if descriptor string doesn't match exactly
      const tokenJaccard = calculateJaccardSimilarity(normQueryFrames.tokens, normRecordFrames.tokens);
      frameOverlapScore = Math.round(tokenJaccard * 0.5 * 10000) / 10000;
      if (frameOverlapScore > 0) {
        reasons.push(`Stack frames share token proximity (Score: ${frameOverlapScore.toFixed(4)})`);
      } else {
        distinguishingDifferences.push('Stack frames have completely divergent call hierarchies');
      }
    }
  } else {
    if (!query.stackFrames || query.stackFrames.length === 0) {
      distinguishingDifferences.push('No stack frames provided in query');
    }
    if (!record.stackFrames || record.stackFrames.length === 0) {
      distinguishingDifferences.push('No stack frames recorded in historical incident');
    }
  }

  // 6. Match Type Classification
  // Correction 1: Strictly requires exact string equality of non-empty normalizedText
  // AND exact string equality of non-empty normalizedPath.
  // Never relies solely on Jaccard score (e.g., token permutations or subsets).
  const hasExactSignature =
    normQuerySig.normalizedText.length > 0 &&
    normRecordSig.normalizedText.length > 0 &&
    normQuerySig.normalizedText === normRecordSig.normalizedText;

  const hasExactTarget =
    normQueryTarget.normalizedPath.length > 0 &&
    normRecordTarget.normalizedPath.length > 0 &&
    normQueryTarget.normalizedPath === normRecordTarget.normalizedPath;

  const isExactMatch = hasExactSignature && hasExactTarget;
  const matchType: 'EXACT' | 'APPROXIMATE' = isExactMatch ? 'EXACT' : 'APPROXIMATE';

  // 7. Calculate overall weighted score
  const rawScore =
    signatureOverlapScore * SIMILARITY_WEIGHTS.SIGNATURE_OVERLAP +
    targetOverlapScore * SIMILARITY_WEIGHTS.TARGET_OVERLAP +
    categoryOverlapScore * SIMILARITY_WEIGHTS.CATEGORY_OVERLAP +
    frameOverlapScore * SIMILARITY_WEIGHTS.FRAME_OVERLAP;

  const overallScore = Math.round(rawScore * 10000) / 10000;

  // 8. Filter by minSimilarityScore
  const threshold = query.minSimilarityScore ?? 0.60;
  if (overallScore < threshold) {
    return null;
  }

  const similarityExplanation: HistoricalMatchExplanation = {
    overallScore,
    matchType,
    similarityFactors: {
      signatureOverlapScore,
      targetOverlapScore,
      categoryOverlapScore,
      frameOverlapScore
    },
    reasons,
    distinguishingDifferences
  };

  const relevanceExplanation = isExactMatch
    ? `Exact match on error signature and target component '${record.affectedTarget}' (Score: ${overallScore.toFixed(2)})`
    : `Approximate similarity match (Score: ${overallScore.toFixed(2)}, Type: ${matchType}) with ${reasons.length} matching factors`;

  return {
    record,
    similarity: similarityExplanation,
    verificationStatus: record.verificationStatus,
    relevanceExplanation
  };
}

/**
 * Deterministically ranks historical matches according to strict tie-breaking rules:
 * 1. overallScore descending
 * 2. matchType (EXACT before APPROXIMATE)
 * 3. record.timestamp descending (more recent first)
 * 4. record.id ascending (stable lexicographical string sort)
 */
export function rankHistoricalMatches(matches: HistoricalIncidentMatch[]): HistoricalIncidentMatch[] {
  return [...matches].sort((a, b) => {
    // 1. Overall score descending
    const scoreDiff = b.similarity.overallScore - a.similarity.overallScore;
    if (Math.abs(scoreDiff) > 1e-6) {
      return scoreDiff;
    }

    // 2. Match type (EXACT before APPROXIMATE)
    if (a.similarity.matchType !== b.similarity.matchType) {
      return a.similarity.matchType === 'EXACT' ? -1 : 1;
    }

    // 3. Record timestamp descending (more recent first)
    const timeA = new Date(a.record.timestamp).getTime();
    const timeB = new Date(b.record.timestamp).getTime();
    if (timeA !== timeB) {
      return timeB - timeA;
    }

    // 4. Record ID ascending (stable lexicographical order)
    return a.record.id.localeCompare(b.record.id);
  });
}
