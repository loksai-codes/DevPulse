import { EventEmitter } from 'node:events';
import { SwitchConnection } from './switch-connection.js';
import { RoomMessageSender } from './room-message-sender.js';
import { NormalizedRoomEvent } from '../types/switch-protocol.js';

export interface SwitchAdapterOptions {
  coreUrl: string;
  agentId: string;
  apiKey: string;
  roomId: string;
  connectionId?: string | undefined;
  reconnect?: boolean | undefined;
  maxReconnectAttempts?: number | undefined;
  webSocketFactory?: ((url: string, protocolsOrOptions?: any) => any) | undefined;
  fetchFn?: typeof fetch | undefined;
}

export class SwitchAdapter extends EventEmitter {
  private connection: SwitchConnection;
  private sender: RoomMessageSender;
  private defaultRoomId: string;

  constructor(options: SwitchAdapterOptions) {
    super();
    this.defaultRoomId = options.roomId;

    this.connection = new SwitchConnection({
      coreUrl: options.coreUrl,
      agentId: options.agentId,
      apiKey: options.apiKey,
      roomId: options.roomId,
      connectionId: options.connectionId,
      reconnect: options.reconnect,
      maxReconnectAttempts: options.maxReconnectAttempts,
      webSocketFactory: options.webSocketFactory
    });

    this.sender = new RoomMessageSender({
      coreUrl: options.coreUrl,
      agentId: options.agentId,
      apiKey: options.apiKey,
      fetchFn: options.fetchFn
    });

    this.setupInternalListeners();
  }

  private setupInternalListeners(): void {
    this.connection.on('status', (status) => this.emit('status', status));
    this.connection.on('open', () => this.emit('open'));
    this.connection.on('close', () => this.emit('close'));
    this.connection.on('error', (err) => this.emit('error', err));
    this.connection.on('evicted', (data) => this.emit('evicted', data));
    this.connection.on('event', (event: NormalizedRoomEvent) => this.emit('message', event));
  }

  public async connect(): Promise<void> {
    await this.connection.connect();
  }

  public async disconnect(): Promise<void> {
    await this.connection.disconnect();
  }

  public getStatus(): string {
    return this.connection.getStatus();
  }

  public getCursor(): number {
    return this.connection.getCursor();
  }

  public getConnectionId(): string {
    return this.connection.getConnectionId();
  }

  /**
   * Sends a message into the configured Switch Room.
   */
  public async sendMessage(
    content: string,
    threadId?: string | null | undefined,
    roomId: string = this.defaultRoomId
  ): Promise<{ success: boolean; data?: unknown }> {
    return this.sender.sendMessage({
      roomId,
      content,
      threadId,
      connectionId: this.connection.getConnectionId()
    });
  }

  /**
   * Sends a targeted message to a peer agent.
   */
  public async sendTargetedMessage(
    targetAgentId: string,
    content: string
  ): Promise<{ success: boolean; data?: unknown }> {
    return this.sender.sendTargetedMessage({
      targetAgentId,
      content,
      connectionId: this.connection.getConnectionId()
    });
  }
}
