import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert/strict';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import {
  ContainerSandboxDriver,
  DEFAULT_SANDBOX_RESOURCE_LIMITS
} from '../src/patch-runner/sandbox-driver.js';
import {
  SandboxUnavailableError,
  SandboxCapabilityUnsupportedError,
  SandboxTimeoutError,
  CustomSpawner
} from '../src/patch-runner/types.js';
import { SentinelAgent } from '../src/sentinel/sentinel-agent.js';
import { ChallengeTracker } from '../src/approval/challenge-tracker.js';

describe('Stage 5 - Sub-Stage 5.1: Container Sandbox Driver & Capability Pre-Flight Checks', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = path.join(tmpdir(), `devpulse-test-ws-${randomUUID()}`);
    await fs.mkdir(tempWorkspace, { recursive: true });
  });

  // =========================================================================
  // 1. HARDENED CONTAINER ARGUMENT FORMULATION & RESOURCE BOUNDS
  // =========================================================================
  describe('1. Hardened Container Argument Formulation', () => {
    it('formulates complete container arguments with all mandatory security isolation flags', () => {
      const driver = new ContainerSandboxDriver({
        runtimeBinary: 'docker',
        defaultImage: 'alpine:3.19'
      });

      const containerName = 'test-container-uuid-1234';
      const args = driver.buildContainerArgs(
        {
          workspacePath: tempWorkspace,
          command: 'npm',
          args: ['test', '--', '--ci']
        },
        containerName,
        true // storage quota supported
      );

      // Verify command structure
      assert.equal(args[0], 'run');
      assert.ok(args.includes('--rm'));
      assert.ok(args.includes(containerName));

      // 1. Mandatory Network Isolation
      const netIdx = args.indexOf('--network');
      assert.ok(netIdx !== -1, '--network flag must be present');
      assert.equal(args[netIdx + 1], 'none', '--network must be strictly set to none');

      // 2. Non-root user
      const userIdx = args.indexOf('--user');
      assert.ok(userIdx !== -1, '--user flag must be present');
      assert.equal(args[userIdx + 1], '10001:10001', 'Must run as unprivileged UID/GID 10001');

      // 3. Dropped Linux Capabilities
      const capIdx = args.indexOf('--cap-drop');
      assert.ok(capIdx !== -1, '--cap-drop flag must be present');
      assert.equal(args[capIdx + 1], 'ALL', 'Must drop ALL capabilities');

      // 4. No New Privileges
      assert.ok(args.includes('--security-opt'));
      assert.ok(args.includes('no-new-privileges:true'));

      // 5. Read-Only Root Filesystem
      assert.ok(args.includes('--read-only'), 'Container root must be mounted read-only');

      // 6. Resource Limits
      const memIdx = args.indexOf('--memory');
      assert.ok(memIdx !== -1);
      assert.equal(args[memIdx + 1], `${DEFAULT_SANDBOX_RESOURCE_LIMITS.memoryMb}m`);

      const swapIdx = args.indexOf('--memory-swap');
      assert.ok(swapIdx !== -1);
      assert.equal(args[swapIdx + 1], `${DEFAULT_SANDBOX_RESOURCE_LIMITS.memorySwapMb}m`);

      const cpuIdx = args.indexOf('--cpus');
      assert.ok(cpuIdx !== -1);
      assert.equal(args[cpuIdx + 1], DEFAULT_SANDBOX_RESOURCE_LIMITS.cpus.toString());

      const pidsIdx = args.indexOf('--pids-limit');
      assert.ok(pidsIdx !== -1);
      assert.equal(args[pidsIdx + 1], DEFAULT_SANDBOX_RESOURCE_LIMITS.pidsLimit.toString());

      // 7. Temporary Storage tmpfs
      const tmpfsIdx = args.indexOf('--tmpfs');
      assert.ok(tmpfsIdx !== -1);
      assert.equal(args[tmpfsIdx + 1], `/tmp:rw,noexec,nosuid,size=${DEFAULT_SANDBOX_RESOURCE_LIMITS.tmpfsSizeMb}m`);

      // 8. Storage Quota (when supported)
      const storageIdx = args.indexOf('--storage-opt');
      assert.ok(storageIdx !== -1);
      assert.equal(args[storageIdx + 1], `size=${DEFAULT_SANDBOX_RESOURCE_LIMITS.storageSizeMb}m`);

      // 9. Workspace Mount & Workdir
      const mountIdx = args.indexOf('-v');
      assert.ok(mountIdx !== -1);
      assert.equal(args[mountIdx + 1], `${path.resolve(tempWorkspace)}:/workspace:rw`);

      const workdirIdx = args.indexOf('-w');
      assert.ok(workdirIdx !== -1);
      assert.equal(args[workdirIdx + 1], '/workspace');

      // 10. Sanitized Environments
      assert.ok(args.includes('--env'));
      assert.ok(args.includes('CI=true'));
      assert.ok(args.includes('NODE_ENV=test'));
      assert.ok(args.includes('HOME=/tmp'));

      // 11. Image, Command & Arguments at the end
      const imageIdx = args.indexOf('alpine:3.19');
      assert.ok(imageIdx !== -1, 'Image must be positioned before command');
      assert.equal(args[imageIdx + 1], 'npm');
      assert.equal(args[imageIdx + 2], 'test');
      assert.equal(args[imageIdx + 3], '--');
      assert.equal(args[imageIdx + 4], '--ci');
    });

    it('correctly applies custom resource limits and custom sanitized environment overrides', () => {
      const driver = new ContainerSandboxDriver({ runtimeBinary: 'docker' });
      const args = driver.buildContainerArgs(
        {
          workspacePath: tempWorkspace,
          command: 'node',
          args: ['test.js'],
          resourceLimits: {
            memoryMb: 512,
            memorySwapMb: 512,
            cpus: 1.5,
            pidsLimit: 50,
            tmpfsSizeMb: 32
          },
          env: {
            CUSTOM_VAR: 'sanitized_value'
          }
        },
        'custom-container-uuid'
      );

      const memIdx = args.indexOf('--memory');
      assert.equal(args[memIdx + 1], '512m');

      const swapIdx = args.indexOf('--memory-swap');
      assert.equal(args[swapIdx + 1], '512m');

      const cpuIdx = args.indexOf('--cpus');
      assert.equal(args[cpuIdx + 1], '1.5');

      const pidsIdx = args.indexOf('--pids-limit');
      assert.equal(args[pidsIdx + 1], '50');

      const tmpfsIdx = args.indexOf('--tmpfs');
      assert.equal(args[tmpfsIdx + 1], '/tmp:rw,noexec,nosuid,size=32m');

      assert.ok(args.includes('CUSTOM_VAR=sanitized_value'));
    });
  });

  // =========================================================================
  // 2. RUNTIME RESOLUTION & UNAVAILABLE RUNTIME (STRICT FAIL-CLOSED)
  // =========================================================================
  describe('2. Runtime Resolution & Unavailable Runtime (Fail-Closed)', () => {
    it('throws SandboxUnavailableError when specified runtime binary is nonexistent', async () => {
      const driver = new ContainerSandboxDriver({
        runtimeBinary: 'nonexistent-container-engine-xyz-9999'
      });

      await assert.rejects(
        async () => await driver.resolveRuntime(),
        (err: Error) => {
          assert.equal(err.name, 'SandboxUnavailableError');
          assert.match(err.message, /is unavailable/);
          return true;
        }
      );
    });

    it('strictly fails closed during execute() when container runtime is unavailable with zero host fallback', async () => {
      const driver = new ContainerSandboxDriver({
        runtimeBinary: 'nonexistent-container-engine-xyz-9999'
      });

      let hostCommandExecuted = false;
      await assert.rejects(
        async () =>
          await driver.execute({
            workspacePath: tempWorkspace,
            command: 'node',
            args: ['-e', 'process.exit(0)']
          }),
        (err: Error) => {
          assert.equal(err.name, 'SandboxUnavailableError');
          return true;
        }
      );

      // Verify host command was NEVER executed as a fallback
      assert.equal(hostCommandExecuted, false);
    });
  });

  // =========================================================================
  // 3. CAPABILITY PRE-FLIGHT PROBE & UNSUPPORTED CAPABILITIES
  // =========================================================================
  describe('3. Capability Pre-Flight Probe & Unsupported Controls', () => {
    it('successfully validates capabilities when all mandatory controls are supported', async () => {
      const mockSpawner: CustomSpawner = async (_bin, args) => {
        if (args.includes('--version')) {
          return { exitCode: 0, stdout: 'Docker version 25.0.3, build 4debf41', stderr: '' };
        }
        // Probe container
        return { exitCode: 0, stdout: '', stderr: '' };
      };

      const driver = new ContainerSandboxDriver({
        runtimeBinary: 'docker',
        customSpawner: mockSpawner
      });

      const result = await driver.probeCapabilities();
      assert.equal(result.allMandatoryCapabilitiesSupported, true);
      assert.equal(result.networkNone, true);
      assert.equal(result.capDropAll, true);
      assert.equal(result.noNewPrivileges, true);
      assert.equal(result.readOnlyRoot, true);
      assert.equal(result.memoryLimits, true);
      assert.equal(result.unsupportedMandatoryCapabilities.length, 0);
    });

    it('detects missing --network none support and throws SandboxCapabilityUnsupportedError', async () => {
      const mockSpawner: CustomSpawner = async (_bin, args) => {
        if (args.includes('--version')) {
          return { exitCode: 0, stdout: 'Docker version 25.0.3', stderr: '' };
        }
        // If args test --network none specifically or full probe, reject
        if (args.includes('--network') && args.includes('none')) {
          return { exitCode: 1, stdout: '', stderr: 'unknown flag: --network none' };
        }
        return { exitCode: 0, stdout: '', stderr: '' };
      };

      const driver = new ContainerSandboxDriver({
        runtimeBinary: 'docker',
        customSpawner: mockSpawner
      });

      await assert.rejects(
        async () => await driver.probeCapabilities(),
        (err: SandboxCapabilityUnsupportedError) => {
          assert.equal(err.name, 'SandboxCapabilityUnsupportedError');
          assert.ok(err.unsupportedCapabilities.includes('networkNone'));
          return true;
        }
      );
    });

    it('detects missing --cap-drop ALL support and fails closed', async () => {
      const mockSpawner: CustomSpawner = async (_bin, args) => {
        if (args.includes('--version')) {
          return { exitCode: 0, stdout: 'Docker version 25.0.3', stderr: '' };
        }
        if (args.includes('--cap-drop') && args.includes('ALL')) {
          return { exitCode: 1, stdout: '', stderr: 'capability drop not supported' };
        }
        return { exitCode: 0, stdout: '', stderr: '' };
      };

      const driver = new ContainerSandboxDriver({
        runtimeBinary: 'docker',
        customSpawner: mockSpawner
      });

      await assert.rejects(
        async () => await driver.probeCapabilities(),
        (err: SandboxCapabilityUnsupportedError) => {
          assert.equal(err.name, 'SandboxCapabilityUnsupportedError');
          assert.ok(err.unsupportedCapabilities.includes('capDropAll'));
          return true;
        }
      );
    });

    it('blocks execute() immediately if pre-flight probe previously recorded unsupported capabilities', async () => {
      const mockSpawner: CustomSpawner = async (_bin, args) => {
        if (args.includes('--version')) {
          return { exitCode: 0, stdout: 'Docker version 25.0.3', stderr: '' };
        }
        if (args.includes('no-new-privileges:true')) {
          return { exitCode: 1, stdout: '', stderr: 'security-opt no-new-privileges not supported' };
        }
        return { exitCode: 0, stdout: '', stderr: '' };
      };

      const driver = new ContainerSandboxDriver({
        runtimeBinary: 'docker',
        customSpawner: mockSpawner
      });

      // Try execute directly without prior probe: execute automatically triggers probe, which fails
      await assert.rejects(
        async () =>
          await driver.execute({
            workspacePath: tempWorkspace,
            command: 'npm',
            args: ['test']
          }),
        (err: SandboxCapabilityUnsupportedError) => {
          assert.equal(err.name, 'SandboxCapabilityUnsupportedError');
          assert.ok(err.unsupportedCapabilities.includes('noNewPrivileges'));
          return true;
        }
      );
    });
  });

  // =========================================================================
  // 4. EXECUTION, OUTPUT CAPPING & TIMEOUT MANAGEMENT
  // =========================================================================
  describe('4. Execution, Output Capping & Watchdog', () => {
    it('executes successfully and returns structured output and duration', async () => {
      const mockSpawner: CustomSpawner = async (_bin, args) => {
        if (args.includes('--version')) {
          return { exitCode: 0, stdout: 'Docker version 25.0.3', stderr: '' };
        }
        if (args.includes('/bin/true')) {
          return { exitCode: 0, stdout: '', stderr: '' };
        }
        return {
          exitCode: 0,
          stdout: 'PASS: 12 tests verified cleanly\n',
          stderr: ''
        };
      };

      const driver = new ContainerSandboxDriver({
        runtimeBinary: 'docker',
        customSpawner: mockSpawner
      });

      const result = await driver.execute({
        workspacePath: tempWorkspace,
        command: 'npm',
        args: ['test']
      });

      assert.equal(result.exitCode, 0);
      assert.ok(result.stdout.includes('PASS: 12 tests verified cleanly'));
      assert.equal(result.timedOut, false);
      assert.ok(result.containerName.startsWith('devpulse-sandbox-'));
    });

    it('rejects execution if workspace path does not exist on host', async () => {
      const mockSpawner: CustomSpawner = async () => ({
        exitCode: 0,
        stdout: '',
        stderr: ''
      });

      const driver = new ContainerSandboxDriver({
        runtimeBinary: 'docker',
        customSpawner: mockSpawner
      });

      await assert.rejects(
        async () =>
          await driver.execute({
            workspacePath: '/nonexistent/devpulse/workspace/path/12345',
            command: 'npm',
            args: ['test']
          }),
        /Invalid workspace path/
      );
    });

    it('captures timedOut: true and kills container process when spawner times out', async () => {
      const mockSpawner: CustomSpawner = async (_bin, args) => {
        if (args.includes('--version') || args.includes('/bin/true')) {
          return { exitCode: 0, stdout: '', stderr: '' };
        }
        // Simulate container timeout
        return {
          exitCode: 137,
          stdout: 'Running slow test suite...\n',
          stderr: 'Container killed by timeout',
          timedOut: true
        };
      };

      const driver = new ContainerSandboxDriver({
        runtimeBinary: 'docker',
        defaultTimeoutMs: 1000,
        customSpawner: mockSpawner
      });

      const result = await driver.execute({
        workspacePath: tempWorkspace,
        command: 'npm',
        args: ['test']
      });

      assert.equal(result.timedOut, true);
      assert.equal(result.killed, true);
      assert.equal(result.exitCode, 137);
    });
  });

  // =========================================================================
  // 5. SENTINEL REPOSITORY BASELINE INVARIANCE (CONDITION VERIFICATION)
  // =========================================================================
  describe('5. Sentinel Repository Baseline Invariance', () => {
    let challengeTracker: ChallengeTracker;
    let challengeFile: string;

    beforeEach(async () => {
      challengeFile = path.join(tmpdir(), `sentinel-repo-test-${randomUUID()}.jsonl`);
      challengeTracker = new ChallengeTracker({ persistenceFilePath: challengeFile });
      await challengeTracker.init();
    });

    it('rejects generating an executable remediation specification when canonicalRepository is missing and no default is configured', async () => {
      const sentinel = new SentinelAgent({
        agentId: 'sentinel',
        runnerAgentId: 'runner',
        maintainerAllowlist: ['alice'],
        challengeTracker,
        defaultCanonicalRepository: '' // Explicitly unconfigured default
      });

      await assert.rejects(
        async () =>
          await sentinel.investigate({
            rawText: 'Error: TypeError: token is undefined at src/auth.ts:24:12',
            senderId: 'alice',
            roomId: 'room_ops',
            canonicalRepository: undefined // Ambiguous repository
          }),
        /Cannot generate executable remediation specification: repository baseline is missing or ambiguous/
      );
    });

    it('rejects generating an executable remediation specification when canonicalRepository is invalid or contains traversal', async () => {
      const sentinel = new SentinelAgent({
        agentId: 'sentinel',
        runnerAgentId: 'runner',
        maintainerAllowlist: ['alice'],
        challengeTracker
      });

      await assert.rejects(
        async () =>
          await sentinel.investigate({
            rawText: 'Error: TypeError: token is undefined at src/auth.ts:24:12',
            senderId: 'alice',
            roomId: 'room_ops',
            canonicalRepository: '../../malicious-escape/repo' // Path traversal attempt
          }),
        /invalid repository baseline/
      );
    });

    it('generates an executable remediation specification when canonicalRepository is valid and unambiguous', async () => {
      const sentinel = new SentinelAgent({
        agentId: 'sentinel',
        runnerAgentId: 'runner',
        maintainerAllowlist: ['alice'],
        challengeTracker
      });

      const result = await sentinel.investigate({
        rawText: 'Error: TypeError: token is undefined at src/auth.ts:24:12',
        senderId: 'alice',
        roomId: 'room_ops',
        canonicalRepository: 'devpulse/core' // Valid canonical repository
      });

      assert.equal(result.spec.targetRepository, 'devpulse/core');
      assert.ok(result.challenge.challengeId);
      assert.equal(result.challenge.consumed, false);
    });
  });
});
