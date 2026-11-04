/**
 * Container Sandbox Driver Domain Types & Custom Errors
 * Stage 5: Sub-Stage 5.1
 */

export type SandboxRuntimeType = 'docker' | 'podman';

export interface SandboxCapabilityProbeResult {
  runtime: SandboxRuntimeType;
  runtimeVersion?: string | undefined;
  networkNone: boolean;
  nonRootUser: boolean;
  capDropAll: boolean;
  noNewPrivileges: boolean;
  readOnlyRoot: boolean;
  memoryLimits: boolean;
  cpuLimits: boolean;
  pidsLimit: boolean;
  tmpfsMount: boolean;
  storageQuota: boolean;
  probeDurationMs: number;
  allMandatoryCapabilitiesSupported: boolean;
  unsupportedMandatoryCapabilities: string[];
}

export interface SandboxResourceLimits {
  /** Maximum number of CPU cores (e.g. 2.0) */
  cpus: number;
  /** Maximum RAM in Megabytes (e.g. 1024) */
  memoryMb: number;
  /** Maximum RAM + Swap in Megabytes. Set equal to memoryMb to disable swap */
  memorySwapMb: number;
  /** Maximum number of concurrent PIDs (threads/processes) (e.g. 100) */
  pidsLimit: number;
  /** Maximum tmpfs size in Megabytes mounted at /tmp (e.g. 64) */
  tmpfsSizeMb: number;
  /** Optional disk storage quota in Megabytes */
  storageSizeMb?: number | undefined;
}

export interface SandboxExecutionOptions {
  /** Host filesystem path to the sanitized execution snapshot (mounted at /workspace) */
  workspacePath: string;
  /** The primary executable to launch inside the container (e.g. 'npm') */
  command: string;
  /** Arguments array passed directly to the command (shell: false) */
  args: string[];
  /** Container image to use (defaults to 'alpine:latest' or configured runtime image) */
  image?: string | undefined;
  /** Explicit resource limits override */
  resourceLimits?: Partial<SandboxResourceLimits> | undefined;
  /** Execution timeout in milliseconds (defaults to 60,000 ms) */
  timeoutMs?: number | undefined;
  /** Custom sanitized environment variables */
  env?: Record<string, string> | undefined;
}

export interface SandboxExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  killed: boolean;
  containerName: string;
}

export interface ContainerSandboxDriverOptions {
  /** Explicit runtime binary path or name (defaults to auto-detect podman -> docker) */
  runtimeBinary?: string | undefined;
  /** Default container image (defaults to 'alpine:latest') */
  defaultImage?: string | undefined;
  /** Default execution timeout in milliseconds (defaults to 60,000 ms) */
  defaultTimeoutMs?: number | undefined;
  /** Maximum captured stdout/stderr buffer size in bytes (defaults to 65,536 / 64 KB) */
  maxOutputBufferBytes?: number | undefined;
  /** Custom command spawner for testing/mocking */
  customSpawner?: CustomSpawner | undefined;
}

export type CustomSpawner = (
  binary: string,
  args: string[],
  options: { shell?: boolean; timeout?: number }
) => Promise<{ exitCode: number; stdout: string; stderr: string; timedOut?: boolean }>;

// Custom Error Classes
export class SandboxUnavailableError extends Error {
  public override readonly name = 'SandboxUnavailableError';
  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class SandboxCapabilityUnsupportedError extends Error {
  public override readonly name = 'SandboxCapabilityUnsupportedError';
  public readonly unsupportedCapabilities: string[];

  constructor(message: string, unsupportedCapabilities: string[]) {
    super(message);
    this.unsupportedCapabilities = unsupportedCapabilities;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class SandboxTimeoutError extends Error {
  public override readonly name = 'SandboxTimeoutError';
  public readonly timeoutMs: number;
  public readonly containerName: string;

  constructor(message: string, timeoutMs: number, containerName: string) {
    super(message);
    this.timeoutMs = timeoutMs;
    this.containerName = containerName;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class SandboxExecutionError extends Error {
  public override readonly name = 'SandboxExecutionError';
  public readonly exitCode: number;
  public readonly stderr: string;

  constructor(message: string, exitCode: number, stderr: string) {
    super(message);
    this.exitCode = exitCode;
    this.stderr = stderr;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

