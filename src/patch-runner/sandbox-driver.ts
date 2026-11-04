import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import {
  SandboxRuntimeType,
  SandboxCapabilityProbeResult,
  SandboxResourceLimits,
  SandboxExecutionOptions,
  SandboxExecutionResult,
  ContainerSandboxDriverOptions,
  SandboxUnavailableError,
  SandboxCapabilityUnsupportedError,
  SandboxTimeoutError
} from './types.js';

export const DEFAULT_SANDBOX_RESOURCE_LIMITS: SandboxResourceLimits = {
  cpus: 2.0,
  memoryMb: 1024,
  memorySwapMb: 1024, // equal to memoryMb to strictly disable swap
  pidsLimit: 100,
  tmpfsSizeMb: 64,
  storageSizeMb: 2048
};

export const MANDATORY_SECURITY_CAPABILITIES = [
  'networkNone',
  'nonRootUser',
  'capDropAll',
  'noNewPrivileges',
  'readOnlyRoot',
  'memoryLimits',
  'cpuLimits',
  'pidsLimit',
  'tmpfsMount'
] as const;

export class ContainerSandboxDriver {
  private runtimeBinary?: string | undefined;
  private defaultImage: string;
  private defaultTimeoutMs: number;
  private maxOutputBufferBytes: number;
  private probeResult: SandboxCapabilityProbeResult | null = null;
  private customSpawner?: ContainerSandboxDriverOptions['customSpawner'];

  constructor(options: ContainerSandboxDriverOptions = {}) {
    this.runtimeBinary = options.runtimeBinary;
    this.defaultImage = options.defaultImage ?? 'alpine:latest';
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 60_000;
    this.maxOutputBufferBytes = options.maxOutputBufferBytes ?? 65_536; // 64 KB
    this.customSpawner = options.customSpawner;
  }

  /**
   * Returns cached probe result, if available.
   */
  public getProbeResult(): SandboxCapabilityProbeResult | null {
    return this.probeResult;
  }

  /**
   * Discovers and verifies the container runtime binary (podman or docker).
   * Spawns strictly with shell: false.
   */
  public async resolveRuntime(): Promise<{ runtime: SandboxRuntimeType; binary: string; version: string }> {
    if (this.runtimeBinary) {
      const probe = await this.executeRaw(this.runtimeBinary, ['--version'], 5000);
      if (probe.exitCode === 0) {
        const type: SandboxRuntimeType = this.runtimeBinary.toLowerCase().includes('podman') ? 'podman' : 'docker';
        return { runtime: type, binary: this.runtimeBinary, version: probe.stdout.trim() };
      }
      throw new SandboxUnavailableError(
        `Configured container runtime '${this.runtimeBinary}' is unavailable: ${probe.stderr || 'Command failed'}`
      );
    }

    // Auto-detect: prefer podman (daemonless/rootless), then docker
    for (const candidate of ['podman', 'docker'] as const) {
      try {
        const probe = await this.executeRaw(candidate, ['--version'], 5000);
        if (probe.exitCode === 0) {
          this.runtimeBinary = candidate;
          return { runtime: candidate, binary: candidate, version: probe.stdout.trim() };
        }
      } catch {
        // Continue candidate search
      }
    }

    throw new SandboxUnavailableError(
      'No container runtime found on system. Both podman and docker are missing or unreachable. Host execution is strictly blocked.'
    );
  }

  /**
   * Performs an ephemeral pre-flight capability probe to verify that all
   * mandatory security isolation controls are supported and enforced by the container daemon.
   * Fails closed if any mandatory control is unsupported or if the runtime is offline.
   */
  public async probeCapabilities(forceRecheck = false): Promise<SandboxCapabilityProbeResult> {
    if (this.probeResult && !forceRecheck) {
      return this.probeResult;
    }

    const { runtime, binary, version } = await this.resolveRuntime();
    const startTime = Date.now();

    // Execute comprehensive probe container
    const probeArgs = [
      'run',
      '--rm',
      '--network', 'none',
      '--user', '10001:10001',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges:true',
      '--read-only',
      '--memory', '128m',
      '--memory-swap', '128m',
      '--cpus', '1.0',
      '--pids-limit', '10',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
      this.defaultImage,
      '/bin/true'
    ];

    const probeExec = await this.executeRaw(binary, probeArgs, 15000);
    const durationMs = Date.now() - startTime;

    if (probeExec.exitCode === 0) {
      // Storage quota probe (storage-opt may depend on overlay2 backing filesystem)
      let storageQuota = false;
      try {
        const storageProbeArgs = [
          'run',
          '--rm',
          '--storage-opt', 'size=256m',
          this.defaultImage,
          '/bin/true'
        ];
        const storageExec = await this.executeRaw(binary, storageProbeArgs, 10000);
        storageQuota = storageExec.exitCode === 0;
      } catch {
        storageQuota = false;
      }

      this.probeResult = {
        runtime,
        runtimeVersion: version,
        networkNone: true,
        nonRootUser: true,
        capDropAll: true,
        noNewPrivileges: true,
        readOnlyRoot: true,
        memoryLimits: true,
        cpuLimits: true,
        pidsLimit: true,
        tmpfsMount: true,
        storageQuota,
        probeDurationMs: durationMs,
        allMandatoryCapabilitiesSupported: true,
        unsupportedMandatoryCapabilities: []
      };

      return this.probeResult;
    }

    // Probe failed: granularly identify which flags failed
    const unsupported: string[] = [];
    const checkFlag = async (flags: string[]): Promise<boolean> => {
      const res = await this.executeRaw(binary, ['run', '--rm', ...flags, this.defaultImage, '/bin/true'], 10000);
      return res.exitCode === 0;
    };

    const networkNone = await checkFlag(['--network', 'none']);
    if (!networkNone) unsupported.push('networkNone');

    const nonRootUser = await checkFlag(['--user', '10001:10001']);
    if (!nonRootUser) unsupported.push('nonRootUser');

    const capDropAll = await checkFlag(['--cap-drop', 'ALL']);
    if (!capDropAll) unsupported.push('capDropAll');

    const noNewPrivileges = await checkFlag(['--security-opt', 'no-new-privileges:true']);
    if (!noNewPrivileges) unsupported.push('noNewPrivileges');

    const readOnlyRoot = await checkFlag(['--read-only']);
    if (!readOnlyRoot) unsupported.push('readOnlyRoot');

    const memoryLimits = await checkFlag(['--memory', '128m', '--memory-swap', '128m']);
    if (!memoryLimits) unsupported.push('memoryLimits');

    const cpuLimits = await checkFlag(['--cpus', '1.0']);
    if (!cpuLimits) unsupported.push('cpuLimits');

    const pidsLimit = await checkFlag(['--pids-limit', '10']);
    if (!pidsLimit) unsupported.push('pidsLimit');

    const tmpfsMount = await checkFlag(['--tmpfs', '/tmp:rw,noexec,nosuid,size=16m']);
    if (!tmpfsMount) unsupported.push('tmpfsMount');

    this.probeResult = {
      runtime,
      runtimeVersion: version,
      networkNone,
      nonRootUser,
      capDropAll,
      noNewPrivileges,
      readOnlyRoot,
      memoryLimits,
      cpuLimits,
      pidsLimit,
      tmpfsMount,
      storageQuota: false,
      probeDurationMs: durationMs,
      allMandatoryCapabilitiesSupported: unsupported.length === 0,
      unsupportedMandatoryCapabilities: unsupported
    };

    if (unsupported.length > 0) {
      throw new SandboxCapabilityUnsupportedError(
        `Container sandbox cannot enforce mandatory security controls: [${unsupported.join(', ')}]. Host execution is strictly blocked.`,
        unsupported
      );
    }

    return this.probeResult;
  }

  /**
   * Constructs the full container argument array for an execution task.
   * Public for deterministic testing and inspection.
   */
  public buildContainerArgs(
    options: SandboxExecutionOptions,
    containerName: string,
    storageQuotaSupported = false
  ): string[] {
    const limits: SandboxResourceLimits = {
      ...DEFAULT_SANDBOX_RESOURCE_LIMITS,
      ...(options.resourceLimits ?? {})
    };

    const resolvedWorkspace = path.resolve(options.workspacePath);

    const args: string[] = [
      'run',
      '--name', containerName,
      '--rm',
      '--network', 'none',
      '--user', '10001:10001',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges:true',
      '--read-only',
      '--memory', `${limits.memoryMb}m`,
      '--memory-swap', `${limits.memorySwapMb}m`,
      '--cpus', limits.cpus.toString(),
      '--pids-limit', limits.pidsLimit.toString(),
      '--tmpfs', `/tmp:rw,noexec,nosuid,size=${limits.tmpfsSizeMb}m`,
      '-v', `${resolvedWorkspace}:/workspace:rw`,
      '-w', '/workspace',
      '--env', 'CI=true',
      '--env', 'NODE_ENV=test',
      '--env', 'HOME=/tmp'
    ];

    if (storageQuotaSupported && limits.storageSizeMb) {
      args.push('--storage-opt', `size=${limits.storageSizeMb}m`);
    }

    if (options.env) {
      for (const [key, value] of Object.entries(options.env)) {
        args.push('--env', `${key}=${value}`);
      }
    }

    args.push(options.image ?? this.defaultImage);
    args.push(options.command);
    args.push(...options.args);

    return args;
  }

  /**
   * Executes a command strictly inside the hardened container sandbox.
   * Enforces zero host fallback.
   */
  public async execute(options: SandboxExecutionOptions): Promise<SandboxExecutionResult> {
    // 1. Pre-flight Capability Verification (Fail-Closed)
    if (!this.probeResult) {
      await this.probeCapabilities();
    }

    if (!this.probeResult?.allMandatoryCapabilitiesSupported) {
      throw new SandboxCapabilityUnsupportedError(
        `Sandbox execution blocked: missing mandatory security capabilities: [${this.probeResult?.unsupportedMandatoryCapabilities.join(', ')}]`,
        this.probeResult?.unsupportedMandatoryCapabilities ?? []
      );
    }

    // 2. Validate workspace path exists
    try {
      const stat = await fs.stat(options.workspacePath);
      if (!stat.isDirectory()) {
        throw new Error(`Workspace path '${options.workspacePath}' is not a directory.`);
      }
    } catch (err) {
      throw new Error(`Invalid workspace path '${options.workspacePath}': ${String(err)}`);
    }

    const { binary } = await this.resolveRuntime();
    const containerName = `devpulse-sandbox-${randomUUID()}`;
    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
    const containerArgs = this.buildContainerArgs(options, containerName, this.probeResult.storageQuota);

    const startTime = Date.now();

    // If customSpawner is supplied (e.g. for testing), use it
    if (this.customSpawner) {
      const customRes = await this.customSpawner(binary, containerArgs, { shell: false, timeout: timeoutMs });
      return {
        exitCode: customRes.exitCode,
        stdout: customRes.stdout,
        stderr: customRes.stderr,
        durationMs: Date.now() - startTime,
        timedOut: customRes.timedOut ?? false,
        killed: customRes.timedOut ?? false,
        containerName
      };
    }

    return new Promise<SandboxExecutionResult>((resolve, reject) => {
      let stdoutAccumulator = '';
      let stderrAccumulator = '';
      let stdoutTruncated = false;
      let stderrTruncated = false;
      let timedOut = false;
      let killed = false;

      const child = spawn(binary, containerArgs, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      // Watchdog Timer for full process tree and container termination
      const timer = setTimeout(async () => {
        timedOut = true;
        killed = true;

        // Force kill container via docker/podman kill
        try {
          const killer = spawn(binary, ['kill', containerName], { shell: false });
          killer.on('error', () => {});
        } catch {
          // ignore kill invocation error
        }

        // Force kill local host process tree
        if (child.pid) {
          if (process.platform === 'win32') {
            try {
              spawn('taskkill', ['/pid', child.pid.toString(), '/T', '/F'], { shell: false });
            } catch {
              child.kill('SIGKILL');
            }
          } else {
            try {
              process.kill(-child.pid, 'SIGKILL');
            } catch {
              child.kill('SIGKILL');
            }
          }
        }
      }, timeoutMs);

      child.stdout.on('data', (chunk: Buffer) => {
        if (stdoutTruncated) return;
        stdoutAccumulator += chunk.toString('utf8');
        if (Buffer.byteLength(stdoutAccumulator, 'utf8') > this.maxOutputBufferBytes) {
          stdoutAccumulator = stdoutAccumulator.slice(0, this.maxOutputBufferBytes) + '\n... [OUTPUT TRUNCATED BY DEVPULSE SANDBOX]';
          stdoutTruncated = true;
        }
      });

      child.stderr.on('data', (chunk: Buffer) => {
        if (stderrTruncated) return;
        stderrAccumulator += chunk.toString('utf8');
        if (Buffer.byteLength(stderrAccumulator, 'utf8') > this.maxOutputBufferBytes) {
          stderrAccumulator = stderrAccumulator.slice(0, this.maxOutputBufferBytes) + '\n... [OUTPUT TRUNCATED BY DEVPULSE SANDBOX]';
          stderrTruncated = true;
        }
      });

      child.on('error', (err) => {
        clearTimeout(timer);
        reject(new SandboxUnavailableError(`Failed to spawn container sandbox process: ${err.message}`));
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        const durationMs = Date.now() - startTime;

        if (timedOut) {
          return reject(
            new SandboxTimeoutError(
              `Sandbox execution timed out after ${timeoutMs}ms (container: ${containerName})`,
              timeoutMs,
              containerName
            )
          );
        }

        resolve({
          exitCode: code ?? 1,
          stdout: stdoutAccumulator,
          stderr: stderrAccumulator,
          durationMs,
          timedOut,
          killed,
          containerName
        });
      });
    });
  }

  /**
   * Helper: spawns a command with timeout and buffers output cleanly with shell: false.
   */
  private async executeRaw(
    binary: string,
    args: string[],
    timeoutMs: number
  ): Promise<{ exitCode: number; stdout: string; stderr: string; timedOut: boolean }> {
    if (this.customSpawner) {
      const res = await this.customSpawner(binary, args, { shell: false, timeout: timeoutMs });
      return {
        exitCode: res.exitCode,
        stdout: res.stdout,
        stderr: res.stderr,
        timedOut: res.timedOut ?? false
      };
    }

    return new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;

      const child = spawn(binary, args, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutMs);

      child.stdout.on('data', (chunk: Buffer) => {
        stdout += chunk.toString('utf8');
      });

      child.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf8');
      });

      child.on('error', (err) => {
        clearTimeout(timer);
        resolve({ exitCode: 127, stdout, stderr: err.message, timedOut });
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({ exitCode: code ?? 1, stdout, stderr, timedOut });
      });
    });
  }
}
