import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { normalizeSwitchFrame } from './switch-event-normalizer.js';

export interface SwitchConnectionOptions {
  coreUrl: string;
  agentId: string;
  apiKey: string;
  roomId: string;
  connectionId?: string | undefined;
  reconnect?: boolean | undefined;
  maxReconnectAttempts?: number | undefined;
  webSocketFactory?: ((url: string, protocolsOrOptions?: any) => any) | undefined;
}

export type ConnectionStatus =
  | 'DISCONNECTED'
  | 'CONNECTING'
  | 'CONNECTED'
  | 'RECONNECTING'
  | 'TERMINATED';

export class SwitchConnection extends EventEmitter {
  private coreUrl: string;
  private agentId: string;
  private apiKey: string;
  private roomId: string;
  private connectionId: string;
  private reconnectEnabled: boolean;
  private maxReconnectAttempts: number;
  private webSocketFactory?: ((url: string, protocolsOrOptions?: any) => any) | undefined;

  private ws: any = null;
  private status: ConnectionStatus = 'DISCONNECTED';
  private cursor: number = 0;
  private generation: string = '';
  private reconnectAttempts: number = 0;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private intentionallyClosed: boolean = false;

  constructor(options: SwitchConnectionOptions) {
    super();
    this.coreUrl = options.coreUrl.replace(/\/+$/, '');
    this.agentId = options.agentId;
    this.apiKey = options.apiKey;
    this.roomId = options.roomId;
    this.connectionId = options.connectionId ?? randomUUID();
    this.reconnectEnabled = options.reconnect ?? true;
    this.maxReconnectAttempts = options.maxReconnectAttempts ?? 10;
    this.webSocketFactory = options.webSocketFactory;
  }

  public getStatus(): ConnectionStatus {
    return this.status;
  }

  public getCursor(): number {
    return this.cursor;
  }

  public getConnectionId(): string {
    return this.connectionId;
  }

  /**
   * Constructs the official Switch Core WebSocket endpoint URL with query parameters.
   */
  public buildWebSocketUrl(): string {
    const wsBase = this.coreUrl.replace(/^http/, 'ws');
    const params = new URLSearchParams({
      connection_id: this.connectionId,
      rooms: this.roomId,
      scope: 'single',
      filter: 'all',
      start_from: this.cursor > 0 ? String(this.cursor) : 'head'
    });

    if (this.generation) {
      params.set('expected_generation', this.generation);
    }

    return `${wsBase}/agents/${encodeURIComponent(this.agentId)}/connection/ws?${params.toString()}`;
  }

  /**
   * Opens the authenticated WebSocket connection to Switch Core.
   */
  public async connect(): Promise<void> {
    if (this.status === 'CONNECTED' || this.status === 'CONNECTING') {
      return;
    }

    this.intentionallyClosed = false;
    this.status = this.reconnectAttempts > 0 ? 'RECONNECTING' : 'CONNECTING';
    this.emit('status', this.status);

    const url = this.buildWebSocketUrl();
    const wsOptions = {
      headers: {
        Authorization: `Bearer ${this.apiKey}`
      }
    };

    try {
      if (this.webSocketFactory) {
        this.ws = this.webSocketFactory(url, wsOptions);
      } else {
        // Use Node 22/24 built-in global WebSocket
        this.ws = new (globalThis as any).WebSocket(url, wsOptions);
      }

      this.setupSocketListeners();
    } catch (err: unknown) {
      this.handleSocketFailure(err instanceof Error ? err : new Error(String(err)));
    }
  }

  private setupSocketListeners(): void {
    if (!this.ws) return;

    this.ws.onopen = () => {
      this.status = 'CONNECTED';
      this.reconnectAttempts = 0;
      this.emit('status', this.status);
      this.emit('open');
    };

    this.ws.onmessage = (event: any) => {
      const rawData = event.data;
      this.handleIncomingRawData(rawData);
    };

    this.ws.onerror = (event: any) => {
      const err = event.error ?? new Error('Switch WebSocket encountered an error');
      this.emit('error', err);
    };

    this.ws.onclose = (event: any) => {
      this.ws = null;
      if (!this.intentionallyClosed) {
        this.handleSocketFailure(new Error(`WebSocket closed: code=${event.code}, reason=${event.reason ?? 'none'}`));
      } else {
        this.status = 'DISCONNECTED';
        this.emit('status', this.status);
        this.emit('close');
      }
    };
  }

  /**
   * Handles incoming text data, dispatches immediate heartbeat pongs,
   * updates cursors, and emits normalized events.
   */
  public handleIncomingRawData(rawData: string | unknown): void {
    const result = normalizeSwitchFrame(rawData, this.agentId);

    switch (result.type) {
      case 'PING':
        // Crucial: Respond immediately with pong carrying highest cursor
        this.sendPong();
        break;

      case 'CONNECTION_STATE':
        this.generation = result.generation;
        if (result.cursor > this.cursor) {
          this.cursor = result.cursor;
        }
        this.emit('connection_state', {
          rooms: result.rooms,
          cursor: result.cursor,
          generation: result.generation
        });
        break;

      case 'EVICTED':
        this.emit('evicted', { code: result.code, reason: result.reason });
        break;

      case 'EVENT':
        if (result.event.sequence > this.cursor) {
          this.cursor = result.event.sequence;
        }
        this.emit('event', result.event);
        break;

      case 'IGNORED':
        this.emit('ignored', result.reason);
        break;
    }
  }

  /**
   * Sends the official Pong frame: {"type": "pong", "cursor": <cursor>}
   */
  public sendPong(): void {
    if (this.ws && this.ws.readyState === 1) { // 1 = OPEN
      const pongFrame = JSON.stringify({
        type: 'pong',
        cursor: this.cursor
      });
      try {
        this.ws.send(pongFrame);
        this.emit('pong', this.cursor);
      } catch (err: unknown) {
        this.emit('error', err instanceof Error ? err : new Error(String(err)));
      }
    }
  }

  private handleSocketFailure(err: Error): void {
    this.status = 'DISCONNECTED';
    this.emit('status', this.status);
    this.emit('error', err);

    if (!this.reconnectEnabled || this.intentionallyClosed) {
      return;
    }

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.status = 'TERMINATED';
      this.emit('status', this.status);
      this.emit('error', new Error(`Maximum reconnect attempts (${this.maxReconnectAttempts}) exceeded`));
      return;
    }

    this.reconnectAttempts++;
    const backoffMs = Math.min(1000 * Math.pow(2, this.reconnectAttempts - 1), 30000);

    this.reconnectTimer = setTimeout(() => {
      this.connect().catch(() => {});
    }, backoffMs);
  }

  /**
   * Gracefully closes the connection and cancels reconnection attempts.
   */
  public async disconnect(): Promise<void> {
    this.intentionallyClosed = true;

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      try {
        this.ws.close(1000, 'DevPulse graceful shutdown');
      } catch {
        // ignore close error
      }
      this.ws = null;
    }

    this.status = 'DISCONNECTED';
    this.emit('status', this.status);
    this.emit('close');
  }
}
