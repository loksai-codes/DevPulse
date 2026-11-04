import { ParsedStackFrame, ParsedStackTrace } from '../types.js';

// V8/Node.js stack trace line: "    at FunctionName (path/file.ts:12:34)" or "    at path/file.ts:12:34"
const V8_FRAME_REGEX = /^\s*at\s+(?:(.*?)\s+\((.*?):(\d+):(\d+)\)|(.*?):(\d+):(\d+))\s*$/;
// TypeScript compiler error: "src/file.ts:12:34 - error TS1234: Message"
const TS_ERROR_REGEX = /^\s*([a-zA-Z0-9_\-\/.\\]+\.[a-zA-Z0-9]+):(\d+):(\d+)\s*(?:-\s*error\s+([A-Z0-9]+):?\s*(.*))?$/;
// Python traceback frame: "  File "path/file.py", line 12, in func"
const PYTHON_FRAME_REGEX = /^\s*File\s+["'](.*?)["'],\s+line\s+(\d+)(?:,\s+in\s+(.*))?$/;

// Error header: "TypeError: Cannot read properties of undefined" or "Error [ERR_ASSERTION]: ..."
const ERROR_HEADER_REGEX = /^\s*(?:Uncaught\s+)?([A-Za-z0-9_]+Error|[A-Za-z0-9_]+Exception|Error)(?:\s*\[([A-Z0-9_]+)\])?:\s*(.*)$/;

/**
 * Robust, deterministic stack trace parser.
 * Handles Node.js/V8, TypeScript compiler output, Python, and malformed inputs.
 */
export function parseStackTrace(input: string): ParsedStackTrace {
  const lines = input.split(/\r?\n/);
  let errorType: string | undefined;
  let errorMessage: string | undefined;
  const frames: ParsedStackFrame[] = [];

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;

    // 1. Check for error header line if not yet discovered
    if (!errorType) {
      const headerMatch = trimmed.match(ERROR_HEADER_REGEX);
      if (headerMatch) {
        errorType = headerMatch[1];
        errorMessage = headerMatch[3]?.trim() || (headerMatch[2] ? `[${headerMatch[2]}]` : undefined);
        continue;
      }

      // Check for TS compiler header
      const tsMatch = trimmed.match(TS_ERROR_REGEX);
      if (tsMatch && tsMatch[4]) {
        errorType = tsMatch[4];
        errorMessage = tsMatch[5]?.trim();
        // Also captures a frame
        const file = normalizeFilePath(tsMatch[1]!);
        const line = parseInt(tsMatch[2]!, 10);
        const column = parseInt(tsMatch[3]!, 10);
        frames.push(classifyFrame(trimmed, file, line, column));
        continue;
      }
    }

    // 2. Parse V8 frame
    const v8Match = rawLine.match(V8_FRAME_REGEX);
    if (v8Match) {
      const functionName = v8Match[1]?.trim();
      const file = normalizeFilePath(v8Match[2] || v8Match[5] || '');
      const lineStr = v8Match[3] || v8Match[6];
      const colStr = v8Match[4] || v8Match[7];
      const line = lineStr ? parseInt(lineStr, 10) : undefined;
      const column = colStr ? parseInt(colStr, 10) : undefined;

      frames.push(classifyFrame(trimmed, file, line, column, functionName));
      continue;
    }

    // 3. Parse Python frame
    const pyMatch = rawLine.match(PYTHON_FRAME_REGEX);
    if (pyMatch) {
      const file = normalizeFilePath(pyMatch[1] || '');
      const line = pyMatch[2] ? parseInt(pyMatch[2], 10) : undefined;
      const functionName = pyMatch[3]?.trim();

      frames.push(classifyFrame(trimmed, file, line, undefined, functionName));
      continue;
    }

    // 4. Fallback: Parse generic TS line without error code
    const genericTsMatch = trimmed.match(TS_ERROR_REGEX);
    if (genericTsMatch) {
      const file = normalizeFilePath(genericTsMatch[1]!);
      const line = parseInt(genericTsMatch[2]!, 10);
      const column = parseInt(genericTsMatch[3]!, 10);
      frames.push(classifyFrame(trimmed, file, line, column));
    }
  }

  // Fallback for raw text without explicit "TypeError:" prefix
  if (!errorType && !errorMessage && lines.length > 0) {
    const firstLine = lines[0]!.trim();
    if (firstLine.includes('Error') || firstLine.includes('Exception') || firstLine.includes('Failed')) {
      errorType = 'Error';
      errorMessage = firstLine;
    }
  }

  // Identify Candidate Culprit Frame:
  // Per refinement 2: "The first application stack frame is only a candidate culprit location, not a confirmed root cause."
  const applicationFrame = frames.find((f) => f.isProjectSource);
  const candidateCulpritFrame = applicationFrame ?? (frames.length > 0 ? frames[0] : undefined);
  const hasApplicationFrame = applicationFrame !== undefined;

  return {
    errorType,
    errorMessage,
    frames,
    candidateCulpritFrame,
    hasApplicationFrame
  };
}

function normalizeFilePath(rawPath: string): string {
  return rawPath.replace(/\\/g, '/').replace(/^\/+/, '');
}

function classifyFrame(
  raw: string,
  file: string,
  line?: number,
  column?: number,
  functionName?: string
): ParsedStackFrame {
  const isRuntimeInternal = file.startsWith('node:') || file.includes('internal/process') || file.includes('internal/modules');
  const isDependency = file.includes('node_modules/') || file.includes('vendor/') || file.includes('site-packages/');
  const isProjectSource = !isRuntimeInternal && !isDependency && file.length > 0;

  return {
    raw,
    file,
    line,
    column,
    functionName,
    isProjectSource,
    isDependency,
    isRuntimeInternal
  };
}

