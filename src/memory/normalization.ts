import { ParsedStackFrame } from '../sentinel/types.js';

export interface NormalizedErrorSignature {
  raw: string;
  normalizedText: string;
  tokens: Set<string>;
  errorType?: string | undefined;
  baseMessage: string;
}

export interface NormalizedTargetComponent {
  raw: string;
  normalizedPath: string;
  segments: string[];
  tokens: Set<string>;
}

// Regex to detect hex memory addresses (e.g. 0x7fff5fbff8c0, 0x00000001)
const HEX_ADDRESS_REGEX = /\b0x[0-9a-fA-F]+\b/g;

// Regex to detect ISO-8601 timestamps
const TIMESTAMP_REGEX = /\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g;

// Regex to detect process IDs and thread IDs
const PID_THREAD_REGEX = /\[(?:pid|thread):\s*\d+\]|\b(?:pid|thread|process)\s*[=:]\s*\d+\b/gi;

// Regex to detect trailing or inline line:col coordinates (e.g. :123:45 or :123)
const LINE_COL_REGEX = /:\d+(?::\d+)?\b/g;

// Regex to detect UUIDs / GUIDs
const UUID_REGEX = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;

// Standard non-alphanumeric token delimiter (splits on whitespace, punctuation, underscores, brackets, etc.)
const TOKEN_SPLIT_REGEX = /[^a-zA-Z0-9]+/;

// Standard Error Header (e.g. "TypeError: cannot read property 'x' of undefined")
const ERROR_HEADER_REGEX = /^([A-Z][a-zA-Z0-9]*(?:Error|Exception|Fault|Failure|Alert))(?:\s*\[[A-Z0-9_]+\])?:\s*(.*)$/s;

/**
 * Normalizes an error signature by removing volatile artifacts (memory addresses,
 * process/thread IDs, timestamps, line numbers) and producing a deterministic token set.
 */
export function normalizeErrorSignature(rawSignature: string): NormalizedErrorSignature {
  if (!rawSignature || typeof rawSignature !== 'string') {
    return {
      raw: rawSignature || '',
      normalizedText: '',
      tokens: new Set<string>(),
      errorType: undefined,
      baseMessage: ''
    };
  }

  const trimmed = rawSignature.trim();
  if (trimmed.length === 0) {
    return {
      raw: rawSignature,
      normalizedText: '',
      tokens: new Set<string>(),
      errorType: undefined,
      baseMessage: ''
    };
  }

  // 1. Check for error type prefix
  let errorType: string | undefined;
  let baseMessage = trimmed;
  const headerMatch = trimmed.match(ERROR_HEADER_REGEX);
  if (headerMatch && headerMatch[1]) {
    errorType = headerMatch[1];
    baseMessage = headerMatch[2] ? headerMatch[2].trim() : '';
  }

  // 2. Strip volatile tokens from signature text
  let cleaned = trimmed
    .replace(HEX_ADDRESS_REGEX, '')
    .replace(TIMESTAMP_REGEX, '')
    .replace(PID_THREAD_REGEX, '')
    .replace(UUID_REGEX, '')
    .replace(LINE_COL_REGEX, '')
    .toLowerCase();

  // Normalize multiple spaces into single space
  cleaned = cleaned.replace(/\s+/g, ' ').trim();

  // 3. Extract tokens
  const rawTokens = cleaned.split(TOKEN_SPLIT_REGEX);
  const tokenSet = new Set<string>();

  for (const token of rawTokens) {
    const t = token.trim();
    // Exclude empty and single-character noise tokens, except meaningful short acronyms if desired
    if (t.length > 1) {
      tokenSet.add(t);
    }
  }

  // If errorType was recognized, ensure it's also lowercased in the token set
  if (errorType) {
    tokenSet.add(errorType.toLowerCase());
  }

  return {
    raw: rawSignature,
    normalizedText: cleaned,
    tokens: tokenSet,
    errorType,
    baseMessage
  };
}

/**
 * Normalizes a target file or module component path.
 * Canonicalizes directory separators, trims leading relative prefixes,
 * lowercases for cross-platform matching, and segments the path.
 */
export function normalizeTargetComponent(rawTarget?: string): NormalizedTargetComponent {
  if (!rawTarget || typeof rawTarget !== 'string') {
    return {
      raw: rawTarget || '',
      normalizedPath: '',
      segments: [],
      tokens: new Set<string>()
    };
  }

  const trimmed = rawTarget.trim();
  if (trimmed.length === 0) {
    return {
      raw: rawTarget,
      normalizedPath: '',
      segments: [],
      tokens: new Set<string>()
    };
  }

  // Standardize backslashes to forward slashes
  let cleanPath = trimmed.replace(/\\/g, '/');

  // Strip leading redundant symbols like "./" or "/"
  cleanPath = cleanPath.replace(/^\.?\/+/, '');

  // Lowercase for uniform deterministic cross-platform comparison
  const normalizedPath = cleanPath.toLowerCase();

  // Segment by directory delimiter
  const segments = normalizedPath.split('/').filter(s => s.length > 0);

  // Extract individual path tokens
  const tokenSet = new Set<string>();
  for (const seg of segments) {
    const subTokens = seg.split(/[^a-zA-Z0-9_$]+/);
    for (const tok of subTokens) {
      if (tok.length > 1) {
        tokenSet.add(tok);
      }
    }
  }

  return {
    raw: rawTarget,
    normalizedPath,
    segments,
    tokens: tokenSet
  };
}

/**
 * Normalizes stack frames into stable, deterministic location descriptors.
 * Ignores ephemeral line/column coordinates, extracting:
 * [normalizedFilePath]:[functionName]
 */
export function normalizeStackFrames(frames?: ParsedStackFrame[]): {
  frameDescriptors: string[];
  tokens: Set<string>;
} {
  if (!frames || !Array.isArray(frames) || frames.length === 0) {
    return {
      frameDescriptors: [],
      tokens: new Set<string>()
    };
  }

  const frameDescriptors: string[] = [];
  const tokenSet = new Set<string>();

  for (const frame of frames) {
    if (!frame.file) continue;

    const normalizedFile = normalizeTargetComponent(frame.file).normalizedPath;
    const fn = frame.functionName ? frame.functionName.trim().toLowerCase() : undefined;

    const desc = fn ? `${normalizedFile}:${fn}` : normalizedFile;
    frameDescriptors.push(desc);

    // Add path segments and function name to tokens
    const fileTokens = normalizeTargetComponent(frame.file).tokens;
    for (const ft of fileTokens) {
      tokenSet.add(ft);
    }
    if (fn) {
      const fnTokens = fn.split(TOKEN_SPLIT_REGEX);
      for (const fnt of fnTokens) {
        if (fnt.length > 1) {
          tokenSet.add(fnt);
        }
      }
    }
  }

  return {
    frameDescriptors,
    tokens: tokenSet
  };
}
