import {
  SwitchDomainEventFrameSchema,
  SwitchMessagePayloadSchema,
  SwitchCommandPayloadSchema,
  NormalizedRoomEvent
} from '../types/switch-protocol.js';

export type NormalizerResult =
  | { type: 'PING' }
  | { type: 'CONNECTION_STATE'; rooms: string[]; cursor: number; generation: string }
  | { type: 'EVICTED'; code: string; reason?: string }
  | { type: 'EVENT'; event: NormalizedRoomEvent }
  | { type: 'IGNORED'; reason: string };

/**
 * Normalizes raw frames received over the Switch WebSocket connection
 * into strongly-typed internal DevPulse representations.
 */
export function normalizeSwitchFrame(
  raw: unknown,
  expectedAgentId: string
): NormalizerResult {
  let parsed: unknown = raw;

  if (typeof raw === 'string') {
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { type: 'IGNORED', reason: 'Malformed non-JSON frame' };
    }
  }

  if (!parsed || typeof parsed !== 'object') {
    return { type: 'IGNORED', reason: 'Frame is not an object' };
  }

  const obj = parsed as Record<string, unknown>;
  const frameType = (obj['type'] ?? obj['event']) as string | undefined;

  // 1. Control Frame: Ping
  if (frameType === 'ping') {
    return { type: 'PING' };
  }

  // 2. Control Frame: Connection State
  if (frameType === 'connection_state') {
    const data = (obj['data'] && typeof obj['data'] === 'object' ? obj['data'] : obj) as Record<string, unknown>;
    const rooms = Array.isArray(data['rooms']) ? (data['rooms'] as string[]) : [];
    const cursor = typeof data['cursor'] === 'number' ? data['cursor'] : 0;
    const generation = data['generation'] !== undefined ? String(data['generation']) : '';
    return {
      type: 'CONNECTION_STATE',
      rooms,
      cursor,
      generation
    };
  }

  // 3. Control Frame: Evicted
  if (frameType === 'evicted') {
    const data = (obj['data'] && typeof obj['data'] === 'object' ? obj['data'] : obj) as Record<string, unknown>;
    const code = typeof data['code'] === 'string' ? data['code'] : 'unknown';
    const reason = typeof data['reason'] === 'string' ? data['reason'] : undefined;
    return {
      type: 'EVICTED',
      code,
      ...(reason ? { reason } : {})
    };
  }

  // 4. Domain Event Frame
  const domainCheck = SwitchDomainEventFrameSchema.safeParse(obj);
  if (!domainCheck.success) {
    return {
      type: 'IGNORED',
      reason: `Unrecognized frame structure: ${domainCheck.error.issues.map((i) => i.message).join(', ')}`
    };
  }

  const frame = domainCheck.data;
  const isNativeConsole = frame.data.bridge_id === null;

  // Handle 'message' event
  if (frame.data.type === 'message') {
    const messagePayloadCheck = SwitchMessagePayloadSchema.safeParse(frame.data.payload);
    if (!messagePayloadCheck.success) {
      return {
        type: 'IGNORED',
        reason: `Invalid message payload: ${messagePayloadCheck.error.issues.map((i) => i.message).join(', ')}`
      };
    }

    const payload = messagePayloadCheck.data;
    const isSelfMessage = payload.sender === expectedAgentId;
    const rawSenderType = (payload as Record<string, unknown>)['sender_type'];
    const senderType =
      rawSenderType === 'USER' || rawSenderType === 'AGENT' || rawSenderType === 'BOT' || rawSenderType === 'SYSTEM'
        ? rawSenderType
        : payload.sender.startsWith('agn_')
          ? 'AGENT'
          : 'USER';

    const normalized: NormalizedRoomEvent = {
      eventId: payload.message_id,
      sequence: frame.data.sequence,
      roomId: frame.data.room_id,
      isNativeConsole,
      bridgeId: frame.data.bridge_id,
      channelType: frame.data.channel_type ?? null,
      senderId: payload.sender,
      senderName: payload.sender_name,
      senderType,
      addressedToMe: payload.addressed,
      body: payload.body,
      timestamp: payload.timestamp,
      threadId: payload.thread_id ?? null,
      isSelfMessage,
      raw: parsed
    };

    return { type: 'EVENT', event: normalized };
  }

  // Handle 'command' event
  if (frame.data.type === 'command') {
    const commandPayloadCheck = SwitchCommandPayloadSchema.safeParse(frame.data.payload);
    if (!commandPayloadCheck.success) {
      return {
        type: 'IGNORED',
        reason: `Invalid command payload: ${commandPayloadCheck.error.issues.map((i) => i.message).join(', ')}`
      };
    }

    const payload = commandPayloadCheck.data;
    const isSelfMessage = payload.user_id === expectedAgentId;

    const normalized: NormalizedRoomEvent = {
      eventId: `cmd_${frame.data.sequence}`,
      sequence: frame.data.sequence,
      roomId: frame.data.room_id,
      isNativeConsole,
      bridgeId: frame.data.bridge_id,
      channelType: frame.data.channel_type ?? null,
      senderId: payload.user_id,
      senderName: payload.user_name,
      senderType: 'USER',
      addressedToMe: true,
      body: `/${payload.command} ${payload.args}`.trim(),
      timestamp: Date.now(),
      threadId: payload.thread_id ?? null,
      isSelfMessage,
      raw: parsed
    };

    return { type: 'EVENT', event: normalized };
  }

  return { type: 'IGNORED', reason: `Unhandled domain event type '${frame.data.type}'` };
}

