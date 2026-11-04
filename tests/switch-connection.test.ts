import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { SwitchConnection } from '../src/room/switch-connection.js';

class MockWebSocket extends EventEmitter {
  public url: string;
  public options: any;
  public readyState: number = 0; // 0 = CONNECTING, 1 = OPEN, 2 = CLOSING, 3 = CLOSED
  public sentMessages: string[] = [];
  public closeCode?: number;
  public closeReason?: string;

  constructor(url: string, options: any) {
    super();
    this.url = url;
    this.options = options;
  }

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

  public simulateClose(code: number = 1000, reason: string = 'Normal'): void {
    this.readyState = 3;
    this.closeCode = code;
    this.closeReason = reason;
    if (this.onclose) this.onclose({ code, reason });
    this.emit('close', { code, reason });
  }

  public send(msg: string): void {
    this.sentMessages.push(msg);
  }

  public close(code: number = 1000, reason?: string): void {
    this.simulateClose(code, reason ?? 'Closed');
  }

  public onopen: (() => void) | null = null;
  public onmessage: ((evt: any) => void) | null = null;
  public onerror: ((evt: any) => void) | null = null;
  public onclose: ((evt: any) => void) | null = null;
}

describe('SwitchConnection WebSocket Lifecycle & Heartbeat Handling', () => {
  const options = {
    coreUrl: 'http://localhost:8080',
    agentId: 'agn_sentinel',
    apiKey: 'sw_test_key_123',
    roomId: 'room_devpulse_ops',
    connectionId: 'conn_test_uuid_1234',
    reconnect: false // Disable auto-reconnect timer for deterministic unit tests
  };

  it('correctly constructs official Switch WebSocket URL with parameters', () => {
    const connection = new SwitchConnection(options);
    const url = connection.buildWebSocketUrl();

    assert.match(url, /^ws:\/\/localhost:8080\/agents\/agn_sentinel\/connection\/ws\?/);
    assert.match(url, /connection_id=conn_test_uuid_1234/);
    assert.match(url, /rooms=room_devpulse_ops/);
    assert.match(url, /scope=single/);
    assert.match(url, /filter=all/);
    assert.match(url, /start_from=head/);
  });

  it('answers incoming ping immediately with pong carrying the latest cursor', async () => {
    let mockWsInstance: MockWebSocket | null = null;
    const connection = new SwitchConnection({
      ...options,
      webSocketFactory: (url, opts) => {
        mockWsInstance = new MockWebSocket(url, opts);
        return mockWsInstance;
      }
    });

    await connection.connect();
    assert.ok(mockWsInstance);
    mockWsInstance.simulateOpen();

    assert.equal(connection.getStatus(), 'CONNECTED');

    // Simulate domain event sequence 100
    mockWsInstance.simulateMessage({
      event: 'message',
      data: {
        type: 'message',
        room_id: 'room_devpulse_ops',
        bridge_id: null,
        sequence: 100,
        payload: {
          addressed: true,
          sender: 'usr_alice',
          sender_name: 'Alice',
          message_id: 'm1',
          body: 'hello',
          timestamp: Date.now()
        }
      },
      id: 100
    });

    assert.equal(connection.getCursor(), 100);

    // Simulate Switch Core server ping frame
    mockWsInstance.simulateMessage({ type: 'ping' });

    // Assert that client sent immediate pong carrying cursor 100
    assert.equal(mockWsInstance.sentMessages.length, 1);
    const pongFrame = JSON.parse(mockWsInstance.sentMessages[0]!);
    assert.deepEqual(pongFrame, { type: 'pong', cursor: 100 });
  });

  it('updates generation and cursor upon receiving connection_state control frame', async () => {
    let mockWsInstance: MockWebSocket | null = null;
    const connection = new SwitchConnection({
      ...options,
      webSocketFactory: (url, opts) => {
        mockWsInstance = new MockWebSocket(url, opts);
        return mockWsInstance;
      }
    });

    await connection.connect();
    mockWsInstance!.simulateOpen();

    let capturedState: any = null;
    connection.on('connection_state', (state) => {
      capturedState = state;
    });

    mockWsInstance!.simulateMessage({
      type: 'connection_state',
      rooms: ['room_devpulse_ops'],
      cursor: 500,
      generation: 'gen_alpha_1'
    });

    assert.equal(connection.getCursor(), 500);
    assert.deepEqual(capturedState, {
      rooms: ['room_devpulse_ops'],
      cursor: 500,
      generation: 'gen_alpha_1'
    });

    // Verify next URL construction includes expected_generation and start_from 500
    const nextUrl = connection.buildWebSocketUrl();
    assert.match(nextUrl, /start_from=500/);
    assert.match(nextUrl, /expected_generation=gen_alpha_1/);
  });

  it('handles graceful disconnect cleanly with code 1000', async () => {
    let mockWsInstance: MockWebSocket | null = null;
    const connection = new SwitchConnection({
      ...options,
      webSocketFactory: (url, opts) => {
        mockWsInstance = new MockWebSocket(url, opts);
        return mockWsInstance;
      }
    });

    await connection.connect();
    mockWsInstance!.simulateOpen();

    let closed = false;
    connection.on('close', () => {
      closed = true;
    });

    await connection.disconnect();

    assert.equal(connection.getStatus(), 'DISCONNECTED');
    assert.equal(mockWsInstance!.closeCode, 1000);
    assert.equal(closed, true);
  });
});

