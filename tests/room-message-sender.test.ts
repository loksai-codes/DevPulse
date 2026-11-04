import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { RoomMessageSender } from '../src/room/room-message-sender.js';

describe('RoomMessageSender Outbound HTTP Client', () => {
  const agentId = 'agn_devpulse_sentinel';
  const apiKey = 'sw_secret_token_12345';
  const coreUrl = 'http://localhost:8080';

  it('posts direct room message via POST /agents/{agentId}/message', async () => {
    let capturedUrl = '';
    let capturedOptions: any = null;

    const mockFetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      capturedUrl = String(input);
      capturedOptions = init;
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    const sender = new RoomMessageSender({
      coreUrl,
      agentId,
      apiKey,
      fetchFn: mockFetch as any
    });

    const result = await sender.sendMessage({
      roomId: 'room_devpulse_ops',
      content: 'Investigation findings: Low risk.'
    });

    assert.equal(result.success, true);
    assert.equal(capturedUrl, 'http://localhost:8080/agents/agn_devpulse_sentinel/message');
    assert.equal(capturedOptions.method, 'POST');
    assert.equal(capturedOptions.headers['Authorization'], `Bearer ${apiKey}`);
    assert.deepEqual(JSON.parse(capturedOptions.body), {
      room_id: 'room_devpulse_ops',
      content: 'Investigation findings: Low risk.'
    });
  });

  it('posts threaded message via POST /agents/{agentId}/ops/post_message with X-Switch-Connection-Id', async () => {
    let capturedUrl = '';
    let capturedOptions: any = null;

    const mockFetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      capturedUrl = String(input);
      capturedOptions = init;
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    const sender = new RoomMessageSender({
      coreUrl,
      agentId,
      apiKey,
      fetchFn: mockFetch as any
    });

    const result = await sender.sendMessage({
      roomId: 'room_devpulse_ops',
      content: 'Replying to incident thread',
      threadId: 'th_issue_42',
      connectionId: 'conn_uuid_9999'
    });

    assert.equal(result.success, true);
    assert.equal(capturedUrl, 'http://localhost:8080/agents/agn_devpulse_sentinel/ops/post_message');
    assert.equal(capturedOptions.headers['X-Switch-Connection-Id'], 'conn_uuid_9999');
    assert.deepEqual(JSON.parse(capturedOptions.body), {
      room_id: 'room_devpulse_ops',
      content: 'Replying to incident thread',
      thread_id: 'th_issue_42'
    });
  });

  it('sends targeted message to a peer agent via send_targeted_message operation', async () => {
    let capturedUrl = '';
    let capturedOptions: any = null;

    const mockFetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      capturedUrl = String(input);
      capturedOptions = init;
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    const sender = new RoomMessageSender({
      coreUrl,
      agentId,
      apiKey,
      fetchFn: mockFetch as any
    });

    const result = await sender.sendTargetedMessage({
      targetAgentId: 'agn_devpulse_runner',
      content: 'Execute remediation spec_1001',
      connectionId: 'conn_uuid_9999'
    });

    assert.equal(result.success, true);
    assert.equal(capturedUrl, 'http://localhost:8080/agents/agn_devpulse_sentinel/ops/send_targeted_message');
    assert.deepEqual(JSON.parse(capturedOptions.body), {
      target_agent_id: 'agn_devpulse_runner',
      content: 'Execute remediation spec_1001'
    });
  });

  it('redacts sensitive API tokens if an HTTP error occurs', async () => {
    const mockFailingFetch = async (): Promise<Response> => {
      return new Response(`Token invalid: ${apiKey}`, { status: 401, statusText: 'Unauthorized' });
    };

    const sender = new RoomMessageSender({
      coreUrl,
      agentId,
      apiKey,
      fetchFn: mockFailingFetch as any
    });

    await assert.rejects(
      async () => {
        await sender.sendMessage({
          roomId: 'room_devpulse_ops',
          content: 'Test content'
        });
      },
      (err: Error) => {
        assert.equal(err.message.includes(apiKey), false);
        assert.match(err.message, /\[REDACTED_API_KEY\]/);
        return true;
      }
    );
  });
});

