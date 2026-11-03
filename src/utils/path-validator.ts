import * as path from 'node:path';
import * as fs from 'node:fs';

/**
 * Windows reserved device names that cannot be used as file names.
 */
const WINDOWS_RESERVED_NAMES = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i;

/**
 * Validates that a file patch path is strictly safe, relative to repository root,
 * and cannot escape the repository sandbox via traversal sequences, Windows vectors,
 * or symbolic links pointing outside the repository root.
 */
export function validateSafeRepoPath(
  rawPath: string,
  repoRoot: string = process.cwd()
): { safe: boolean; normalizedPath?: string; reason?: string } {
  if (!rawPath || typeof rawPath !== 'string') {
    return { safe: false, reason: 'Path must be a non-empty string' };
  }

  // 1. Check for null bytes (\0 injection)
  if (rawPath.includes('\0')) {
    return { safe: false, reason: 'Null byte injection detected in path' };
  }

  const trimmed = rawPath.trim();
  if (trimmed.length === 0) {
    return { safe: false, reason: 'Path cannot be whitespace only' };
  }

  // 2. Check for Windows drive letters (e.g., C:, D:, c:\)
  if (/^[a-zA-Z]:/i.test(trimmed)) {
    return { safe: false, reason: 'Windows drive letters are forbidden in relative patch paths' };
  }

  // 3. Check for UNC paths (e.g. \\server\share or //server/share)
  if (/^(\\\\|\/\/)/.test(trimmed)) {
    return { safe: false, reason: 'UNC network paths are forbidden' };
  }

  // 4. Check for leading slashes or backslashes
  if (trimmed.startsWith('/') || trimmed.startsWith('\\')) {
    return { safe: false, reason: 'Patch paths must be relative to repository root and cannot start with a slash' };
  }

  // 5. Check for directory traversal sequences (..)
  const segments = trimmed.split(/[/\\]/);
  for (const seg of segments) {
    if (seg === '..') {
      return { safe: false, reason: 'Directory traversal sequence (..) is forbidden' };
    }
    // 6. Check for Windows reserved device names (CON, NUL, AUX, etc.)
    if (WINDOWS_RESERVED_NAMES.test(seg)) {
      return { safe: false, reason: `Windows reserved device name '${seg}' is forbidden` };
    }
  }

  // 7. Resolve string path against repository root and verify containment
  const resolvedRepoRoot = path.resolve(repoRoot);
  const resolvedTarget = path.resolve(resolvedRepoRoot, trimmed);

  const relative = path.relative(resolvedRepoRoot, resolvedTarget);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    return { safe: false, reason: 'Resolved path escapes repository root boundary' };
  }

  // 8. Symbolic Link Security: Inspect existing components on disk to prevent symlink breakout
  try {
    let current = resolvedRepoRoot;
    for (const seg of segments) {
      if (!seg) continue;
      current = path.join(current, seg);
      if (fs.existsSync(current)) {
        const real = fs.realpathSync(current);
        const relToRoot = path.relative(resolvedRepoRoot, real);
        if (relToRoot.startsWith('..') || path.isAbsolute(relToRoot)) {
          return { safe: false, reason: 'Symbolic link escapes repository root boundary' };
        }
      }
    }
  } catch (err: unknown) {
    return {
      safe: false,
      reason: 'Failed to verify symbolic link safety: ' + (err instanceof Error ? err.message : String(err))
    };
  }

  // Normalize path using standard forward slashes for cross-platform Git compatibility
  const normalizedPath = segments.filter(Boolean).join('/');
  return { safe: true, normalizedPath };
}
