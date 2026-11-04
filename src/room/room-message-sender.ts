import { OutboundMessageSchema } from '../types/switch-protocol.js';

export interface RoomMessageSenderOptions {
  coreUrl: string;
  agentId: string;
  apiKey: string;
  fetchFn?: typeof fetch | undefined;
}

export interface PostMessageOptions {
  roomId: string;
  content: string;
  threadId?: string | null | undefined;
  connectionId?: string | undefined;
}

export interface TargetedMessageOptions {
  targetAgentId: string;
  content: string;
  connectionId?: string | undefined;
}

export class RoomMessageSender {
  private coreUrl: string;
  private agentId: string;
  private apiKey: string;
  private fetchFn: typeof fetch;

  constructor(options: RoomMessageSenderOptions) {
    this.coreUrl = options.coreUrl.replace(/\/+$/, '');
    this.agentId = options.agentId;
    this.apiKey = options.apiKey;
    this.fetchFn = options.fetchFn ?? globalThis.fetch;
  }

  /**
   * Posts a message into a Switch Room.
   * Uses POST /agents/{agent_id}/ops/post_message if connectionId is provided (for thread correlation),
   * or direct POST /agents/{agent_id}/message otherwise.
   */
  public async sendMessage(options: PostMessageOptions): Promise<{ success: boolean; data?: unknown }> {
    OutboundMessageSchema.parse({
      room_id: options.roomId,
      content: options.content,
      thread_id: options.threadId ?? undefined
    });

    const isOps = Boolean(options.connectionId || options.threadId);
    const endpoint = isOps
      ? `${this.coreUrl}/agents/${encodeURIComponent(this.agentId)}/ops/post_message`
      : `${this.coreUrl}/agents/${encodeURIComponent(this.agentId)}/message`;

    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json'
    };

    if (options.connectionId) {
      headers['X-Switch-Connection-Id'] = options.connectionId;
    }

    const bodyPayload = isOps
      ? {
          room_id: options.roomId,
          content: options.content,
          ...(options.threadId ? { thread_id: options.threadId } : {})
        }
      : {
          room_id: options.roomId,
          content: options.content
        };

    try {
      const response = await this.fetchFn(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(bodyPayload)
      });

      if (!response.ok) {
        const status = response.status;
        const errText = await response.text().catch(() => '');
        throw new Error(`Switch post_message failed [HTTP ${status}]: ${errText || response.statusText}`);
      }

      const data = await response.json().catch(() => ({}));
      return { success: true, data };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      // Ensure token is never leaked in the error message
      const sanitized = message.replace(this.apiKey, '[REDACTED_API_KEY]');
      throw new Error(`RoomMessageSender error: ${sanitized}`);
    }
  }

  /**
   * Sends a targeted message to a specific peer agent in the room.
   * Documented API: POST /agents/{agent_id}/ops/send_targeted_message
   */
  public async sendTargetedMessage(options: TargetedMessageOptions): Promise<{ success: boolean; data?: unknown }> {
    const endpoint = `${this.coreUrl}/agents/${encodeURIComponent(this.agentId)}/ops/send_targeted_message`;

    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json'
    };

    if (options.connectionId) {
      headers['X-Switch-Connection-Id'] = options.connectionId;
    }

    const payload = {
      target_agent_id: options.targetAgentId,
      content: options.content
    };

    try {
      const response = await this.fetchFn(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errText = await response.text().catch(() => '');
        throw new Error(`Switch send_targeted_message failed [HTTP ${response.status}]: ${errText || response.statusText}`);
      }

      const data = await response.json().catch(() => ({}));
      return { success: true, data };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      const sanitized = message.replace(this.apiKey, '[REDACTED_API_KEY]');
      throw new Error(`RoomMessageSender error: ${sanitized}`);
    }
  }
}
