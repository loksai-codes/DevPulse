import { z } from 'zod';

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
  actor: HumanIdentitySchema,
  decision: ApprovalDecisionSchema,
  approvedAt: z.string().datetime({ message: 'approvedAt must be an ISO-8601 string' }),
  nonce: z.string().min(16, 'nonce must be at least 16 characters long'),
  reason: z.string().optional(),
  signature: z.string().min(1, 'Cryptographic or HMAC binding signature is required')
});

export type HumanApproval = z.infer<typeof HumanApprovalSchema>;

/**
 * Trusted event metadata directly emitted by Switch Console / Room Gateway.
 * Cannot be forged by message contents or unprivileged participants.
 */
export const SwitchRoomEventMetadataSchema = z.object({
  roomId: z.string().min(1),
  senderId: z.string().min(1),
  senderUsername: z.string().min(1),
  senderType: z.literal('human', {
    description: 'Only human participants may approve; bot/agent senders are rejected'
  }),
  roomRole: AuthorizedRoleSchema,
  timestamp: z.string().datetime()
});
export type SwitchRoomEventMetadata = z.infer<typeof SwitchRoomEventMetadataSchema>;

/**
 * Validates whether a Switch room event genuinely represents an authorized human operator.
 */
export function verifyTrustedRoomAuthorization(
  event: SwitchRoomEventMetadata,
  allowedUserIds?: string[]
): { authorized: boolean; reason?: string } {
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
