import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { SwitchAdapter } from '../src/room/switch-adapter.js';

class MockWebSocket extends EventEmitter {
  public readyState: number = 0;
  public sentMessages: string[] = [];
  public closeCode?: number;

  public simulateOpen(): void {
    this.readyState = 1;
    if (this.onopen) this.onopen();
    this.emit('open');
  }

  public simulateMessage(data: string | unknown): void {
    const raw = typeof data === 'string' ? data : JSON.stringify(data);
    if (this.onmessage) this.onmessage({ data: raw });
    this.emit('message', { data: raw });
  }

  public simulateClose(code: number = 1000): void {
    this.readyState = 3;
    this.closeCode = code;
    if (this.onclose) this.onclose({ code });
    this.emit('close', { code });
  }

  public send(msg: string): void {
    this.sentMessages.push(msg);
  }

  public close(code: number = 1000): void {
    this.simulateClose(code);
  }

  public onopen: (() => void) | null = null;
  public onmessage: ((evt: any) => void) | null = null;
  public onerror: ((evt: any) => void) | null = null;
  public onclose: ((evt: any) => void) | null = null;
}

describe('SwitchAdapter High-Level Room Facade', () => {
  it('connects, normalizes incoming room events, and emits typed message events', async () => {
    let mockWsInstance: MockWebSocket | null = null;

    const mockFetch = async (): Promise<Response> => {
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    const adapter = new SwitchAdapter({
      coreUrl: 'http://localhost:8080',
      agentId: 'agn_sentinel',
      apiKey: 'sw_key_123',
      roomId: 'room_devpulse_ops',
      connectionId: 'conn_test_adapter_1',
      reconnect: false,
      webSocketFactory: (url, opts) => {
        mockWsInstance = new MockWebSocket();
        return mockWsInstance;
      },
      fetchFn: mockFetch as any
    });

    let receivedEvent: any = null;
    adapter.on('message', (event) => {
      receivedEvent = event;
    });

    await adapter.connect();
    mockWsInstance!.simulateOpen();

    assert.equal(adapter.getStatus(), 'CONNECTED');

    // Simulate incoming native Switch Console domain event
    mockWsInstance!.simulateMessage({
      event: 'message',
      data: {
        type: 'message',
        room_id: 'room_devpulse_ops',
        bridge_id: null,
        sequence: 1,
        payload: {
          addressed: true,
          sender: 'usr_maintainer_bob',
          sender_name: 'Bob',
          message_id: 'msg_01',
          body: 'Investigate incident in src/auth.ts',
          timestamp: 1730720000000
        }
      },
      id: 1
    });

    assert.ok(receivedEvent);
    assert.equal(receivedEvent.senderId, 'usr_maintainer_bob');
    assert.equal(receivedEvent.isNativeConsole, true);
    assert.equal(receivedEvent.sequence, 1);

    // Send a room message
    const sendResult = await adapter.sendMessage('Acknowledged incident');
    assert.equal(sendResult.success, true);

    // Disconnect cleanly
    await adapter.disconnect();
    assert.equal(adapter.getStatus(), 'DISCONNECTED');
  });
});

