import { z } from 'zod';

// ==========================================
// 1. Inbound Control Frames
// ==========================================

export const SwitchPingFrameSchema = z.object({
  type: z.literal('ping')
});
export type SwitchPingFrame = z.infer<typeof SwitchPingFrameSchema>;

export const SwitchPongFrameSchema = z.object({
  type: z.literal('pong'),
  cursor: z.number().int().nonnegative()
});
export type SwitchPongFrame = z.infer<typeof SwitchPongFrameSchema>;

export const SwitchConnectionStateFrameSchema = z.object({
  type: z.literal('connection_state'),
  rooms: z.array(z.string()),
  cursor: z.number().int().nonnegative(),
  generation: z.string()
});
export type SwitchConnectionStateFrame = z.infer<typeof SwitchConnectionStateFrameSchema>;

export const SwitchEvictedFrameSchema = z.object({
  type: z.literal('evicted'),
  code: z.string(),
  reason: z.string().optional()
});
export type SwitchEvictedFrame = z.infer<typeof SwitchEvictedFrameSchema>;

// ==========================================
// 2. Inbound Domain Event Payloads
// ==========================================

export const SwitchMessagePayloadSchema = z.object({
  addressed: z.boolean(),
  sender: z.string().min(1),
  sender_name: z.string().min(1),
  message_id: z.string().min(1),
  body: z.string(),
  timestamp: z.number(),
  thread_id: z.string().nullable().optional(),
  attachments: z.array(z.unknown()).optional().default([])
});
export type SwitchMessagePayload = z.infer<typeof SwitchMessagePayloadSchema>;

export const SwitchCommandPayloadSchema = z.object({
  command: z.string().min(1),
  args: z.string().optional().default(''),
  user_id: z.string().min(1),
  user_name: z.string().min(1),
  thread_id: z.string().nullable().optional()
});
export type SwitchCommandPayload = z.infer<typeof SwitchCommandPayloadSchema>;

export const SwitchDomainEventDataSchema = z.object({
  type: z.enum(['message', 'command', 'room_join']),
  room_id: z.string().min(1),
  bridge_id: z.string().nullable(),
  channel_type: z.string().nullable().optional(),
  sequence: z.number().int().nonnegative(),
  payload: z.record(z.unknown())
});
export type SwitchDomainEventData = z.infer<typeof SwitchDomainEventDataSchema>;

export const SwitchDomainEventFrameSchema = z.object({
  event: z.string().min(1),
  data: SwitchDomainEventDataSchema,
  id: z.number().int().nonnegative()
});
export type SwitchDomainEventFrame = z.infer<typeof SwitchDomainEventFrameSchema>;

// ==========================================
// 3. Outbound Message Payload
// ==========================================

export const OutboundMessageSchema = z.object({
  room_id: z.string().min(1),
  content: z.string().min(1, 'Message content cannot be empty'),
  thread_id: z.string().nullable().optional()
});
export type OutboundMessage = z.infer<typeof OutboundMessageSchema>;

// ==========================================
// 4. Normalized DevPulse Room Event
// ==========================================

export const NormalizedRoomEventSchema = z.object({
  eventId: z.string().min(1),
  sequence: z.number().int().nonnegative(),
  roomId: z.string().min(1),
  isNativeConsole: z.boolean({
    description: 'True strictly if bridge_id === null (originates natively in Switch Console, not a bridged puppet)'
  }),
  bridgeId: z.string().nullable(),
  channelType: z.string().nullable(),
  senderId: z.string().min(1),
  senderName: z.string().min(1),
  senderType: z.enum(['USER', 'AGENT', 'BOT', 'SYSTEM']).optional(),
  addressedToMe: z.boolean(),
  body: z.string(),
  timestamp: z.number(),
  threadId: z.string().nullable(),
  isSelfMessage: z.boolean({
    description: 'True if message was sent by this agent itself'
  }),
  raw: z.unknown()
});
export type NormalizedRoomEvent = z.infer<typeof NormalizedRoomEventSchema>;

