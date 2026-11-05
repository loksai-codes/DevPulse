import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseEnv, updateEnvString, registerGateAgent } from '../src/gate/register.js';
import { DevPulseGateServer } from '../src/gate/index.js';

describe('DevPulse Gate & Registration Unit Tests', () => {
  it('parses .env content accurately without quotes', () => {
    const raw = `
# Comment
SWITCH_CORE_URL="http://localhost:8080"
SWITCH_REGISTRATION_KEY='test-reg-key'
ALERT_PORT=3030
`;
    const parsed = parseEnv(raw);
    assert.equal(parsed['SWITCH_CORE_URL'], 'http://localhost:8080');
    assert.equal(parsed['SWITCH_REGISTRATION_KEY'], 'test-reg-key');
    assert.equal(parsed['ALERT_PORT'], '3030');
  });

  it('updates existing keys and appends new keys in .env string', () => {
    const original = 'SWITCH_CORE_URL=http://localhost:8080\nMAINTAINER_ALLOWLIST=usr_1\n';
    const updated = updateEnvString(original, {
      SWITCH_AGENT_ID: 'agn_gate_123',
      MAINTAINER_ALLOWLIST: 'usr_2'
    });

    assert.ok(updated.includes('MAINTAINER_ALLOWLIST=usr_2'));
    assert.ok(updated.includes('SWITCH_AGENT_ID=agn_gate_123'));
    assert.ok(updated.includes('SWITCH_CORE_URL=http://localhost:8080'));
  });

  it('handles agent registration protocol flow (mock HTTP)', async () => {
    const mockCalls: { url: string; method?: string; body?: string }[] = [];

    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      mockCalls.push({ url, method: init?.method, body: init?.body as string });

      if (url.endsWith('/health')) {
        return new Response(JSON.stringify({ status: 'healthy' }), { status: 200 });
      }

      if (url.endsWith('/agents') && init?.method === 'POST') {
        return new Response(JSON.stringify({
          agent_id: 'agn_devpulse_gate',
          api_key: 'sw_mock_secret_key'
        }), { status: 201 });
      }

      if (url.includes('/ops/update_agent_detail')) {
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }

      return new Response('Not found', { status: 404 });
    };

    const tempEnvPath = './logs/test-register.env';
    const result = await registerGateAgent({
      coreUrl: 'http://localhost:8080',
      registrationKey: 'sw_mock_reg_key',
      envPath: tempEnvPath,
      fetchFn: mockFetch as unknown as typeof fetch
    });

    assert.equal(result.success, true);
    assert.equal(result.agentId, 'agn_devpulse_gate');
    assert.ok(mockCalls.some(c => c.url.endsWith('/agents') && c.method === 'POST'));
    assert.ok(mockCalls.some(c => c.url.includes('/ops/update_agent_detail')));
  });

  it('rejects external bridged chat origins from authorizing approvals', async () => {
    const messagesSent: string[] = [];
    const mockAdapter = {
      on: () => {},
      sendMessage: async (msg: string) => { messagesSent.push(msg); }
    } as any;

    const server = new DevPulseGateServer({
      coreUrl: 'http://localhost:8080',
      agentId: 'agn_gate',
      roomId: 'room_test',
      maintainers: ['usr_alice'],
      adapter: mockAdapter
    });

    // Event originating from Slack bridge
    await server.handleRoomMessage({
      eventId: 'evt_1',
      sequence: 1,
      roomId: 'room_test',
      isNativeConsole: false,
      bridgeId: 'bridge_slack_1',
      channelType: 'slack',
      senderId: 'usr_alice',
      senderName: 'Alice',
      senderType: 'USER',
      addressedToMe: true,
      body: '@devpulse-gate approve INC-101 a1b2c3d4e5f6',
      timestamp: Date.now(),
      threadId: null,
      isSelfMessage: false,
      raw: {}
    });

    assert.equal(messagesSent.length, 1);
    assert.ok(messagesSent[0]?.includes('[APPROVAL FORBIDDEN]'));
    assert.ok(messagesSent[0]?.includes('external bridged chat'));
  });

  it('rejects bot/agent sender types from authorizing approvals', async () => {
    const messagesSent: string[] = [];
    const mockAdapter = {
      on: () => {},
      sendMessage: async (msg: string) => { messagesSent.push(msg); }
    } as any;

    const server = new DevPulseGateServer({
      coreUrl: 'http://localhost:8080',
      agentId: 'agn_gate',
      roomId: 'room_test',
      maintainers: ['usr_alice'],
      adapter: mockAdapter
    });

    // Event originating from an agent
    await server.handleRoomMessage({
      eventId: 'evt_2',
      sequence: 2,
      roomId: 'room_test',
      isNativeConsole: true,
      bridgeId: null,
      channelType: null,
      senderId: 'usr_alice',
      senderName: 'Alice',
      senderType: 'AGENT',
      addressedToMe: true,
      body: '@devpulse-gate approve INC-101 a1b2c3d4e5f6',
      timestamp: Date.now(),
      threadId: null,
      isSelfMessage: false,
      raw: {}
    });

    assert.equal(messagesSent.length, 1);
    assert.ok(messagesSent[0]?.includes('Autonomous agents or bots cannot authorize'));
  });

  it('rejects users not present in MAINTAINER_ALLOWLIST', async () => {
    const messagesSent: string[] = [];
    const mockAdapter = {
      on: () => {},
      sendMessage: async (msg: string) => { messagesSent.push(msg); }
    } as any;

    const server = new DevPulseGateServer({
      coreUrl: 'http://localhost:8080',
      agentId: 'agn_gate',
      roomId: 'room_test',
      maintainers: ['usr_alice'],
      adapter: mockAdapter
    });

    // Event originating from an unlisted human user
    await server.handleRoomMessage({
      eventId: 'evt_3',
      sequence: 3,
      roomId: 'room_test',
      isNativeConsole: true,
      bridgeId: null,
      channelType: null,
      senderId: 'usr_mallory',
      senderName: 'Mallory',
      senderType: 'USER',
      addressedToMe: true,
      body: '@devpulse-gate approve INC-101 a1b2c3d4e5f6',
      timestamp: Date.now(),
      threadId: null,
      isSelfMessage: false,
      raw: {}
    });

    assert.equal(messagesSent.length, 1);
    assert.ok(messagesSent[0]?.includes('not in the MAINTAINER_ALLOWLIST'));
  });
});
