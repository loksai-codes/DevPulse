import { z } from 'zod';
import { createHmac } from 'node:crypto';

export const AuthorizedRoleSchema = z.enum(['MAINTAINER', 'ADMIN', 'SECURITY_LEAD']);
export type AuthorizedRole = z.infer<typeof AuthorizedRoleSchema>;

export const HumanIdentitySchema = z.object({
  userId: z.string().min(1, 'User ID cannot be empty'),
  username: z.string().min(1, 'Username cannot be empty'),
  role: AuthorizedRoleSchema,
  channel: z.literal('SWITCH_ROOM', {
    description: 'Approvals must originate directly from authorized Switch room participation'
  })
});
export type HumanIdentity = z.infer<typeof HumanIdentitySchema>;

export const ApprovalDecisionSchema = z.enum(['APPROVED', 'REJECTED']);
export type ApprovalDecision = z.infer<typeof ApprovalDecisionSchema>;

export const HumanApprovalSchema = z.object({
  approvalId: z.string().uuid('approvalId must be a valid UUID to prevent replay attacks'),
  specId: z.string().min(1, 'Specification ID is required'),
  diffHash: z.string().regex(/^[a-f0-9]{64}$/i, 'diffHash must match exact 64-char SHA-256 string'),
  specHash: z.string().regex(/^[a-f0-9]{64}$/i, 'specHash must match exact 64-char SHA-256 string').optional(),
  actor: HumanIdentitySchema,
  decision: ApprovalDecisionSchema,
  approvedAt: z.string().datetime({ message: 'approvedAt must be an ISO-8601 string' }),
  nonce: z.string().min(16, 'nonce must be at least 16 characters long'),
  reason: z.string().optional(),
  signature: z.string().min(1, 'Cryptographic or HMAC binding signature is required')
});

export type HumanApproval = z.infer<typeof HumanApprovalSchema>;

/**
 * Authenticated event envelope emitted by the Switch Console Gateway.
 * Carries a gateway-level cryptographic HMAC signature preventing
 * unauthenticated actors from forging event metadata.
 */
export const SwitchRoomEventMetadataSchema = z.object({
  roomId: z.string().min(1),
  senderId: z.string().min(1),
  senderUsername: z.string().min(1),
  senderType: z.literal('human', {
    description: 'Only human participants may approve; bot/agent senders are rejected'
  }),
  roomRole: AuthorizedRoleSchema,
  timestamp: z.string().datetime(),
  gatewaySignature: z.string().min(1, 'Cryptographic signature from Switch Gateway is required')
});
export type SwitchRoomEventMetadata = z.infer<typeof SwitchRoomEventMetadataSchema>;

/**
 * Computes the expected Switch Console Gateway HMAC signature for a room event envelope.
 */
export function computeGatewaySignature(
  event: Omit<SwitchRoomEventMetadata, 'gatewaySignature'>,
  gatewaySecret: string
): string {
  const payload = [
    event.roomId,
    event.senderId,
    event.senderUsername,
    event.senderType,
    event.roomRole,
    event.timestamp
  ].join(':');
  return createHmac('sha256', gatewaySecret).update(payload, 'utf8').digest('hex');
}

/**
 * Validates whether a Switch room event genuinely represents an authorized human operator:
 * 1. Verifies the cryptographic gateway signature (proves authenticity, not forged).
 * 2. Verifies senderType is strictly 'human'.
 * 3. Verifies senderId against the allowed maintainer list.
 */
export function verifyTrustedRoomAuthorization(
  event: SwitchRoomEventMetadata,
  allowedUserIds?: string[],
  gatewaySecret?: string
): { authorized: boolean; reason?: string } {
  // If gatewaySecret is supplied, verify the cryptographic proof of authenticity
  if (gatewaySecret) {
    const { gatewaySignature, ...unsigned } = event;
    const expected = computeGatewaySignature(unsigned, gatewaySecret);
    if (gatewaySignature !== expected) {
      return {
        authorized: false,
        reason: 'Invalid Switch Gateway signature. Event origin is unverified or forged.'
      };
    }
  }

  if (event.senderType !== 'human') {
    return {
      authorized: false,
      reason: `Unauthorized sender type '${event.senderType}'. Only human operators may issue approvals.`
    };
  }

  if (allowedUserIds && allowedUserIds.length > 0 && !allowedUserIds.includes(event.senderId)) {
    return {
      authorized: false,
      reason: `User '${event.senderId}' is not in the allowed approver list.`
    };
  }

  return { authorized: true };
}
