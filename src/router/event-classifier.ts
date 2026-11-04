import { NormalizedRoomEvent } from '../types/switch-protocol.js';

export type EventCategory =
  | { kind: 'APPROVAL_COMMAND'; challengeId: string; rawSignature?: string | undefined }
  | { kind: 'INCIDENT_REPORT'; text: string }
  | { kind: 'PEER_AGENT_MESSAGE'; payload: Record<string, unknown> }
  | { kind: 'IGNORED'; reason: string };

const APPROVAL_REGEX = /(?:@devpulse\s+)?(?:approve|\/approve)\s+(appr_[a-f0-9]{8,16})(?:\s+(?:sig:)?([a-f0-9]{32,128}))?/i;

export function classifyEvent(
  event: NormalizedRoomEvent,
  sentinelAgentId: string,
  runnerAgentId: string
): EventCategory {
  // 1. Self-Message Filter: Ignore own messages
  if (event.isSelfMessage) {
    return { kind: 'IGNORED', reason: 'Self-message dropped to prevent infinite loops' };
  }

  const trimmed = event.body.trim();
  const isPeerAgent = event.senderId === sentinelAgentId || event.senderId === runnerAgentId;

  // 2. Structured Agent Message: Check if the body contains a JSON agent-to-agent contract
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object' && 'type' in parsed) {
        return { kind: 'PEER_AGENT_MESSAGE', payload: parsed };
      }
    } catch {
      // Not a JSON message, continue parsing as human text
    }
  }

  // Known peer agents should only exchange structured contracts, not chat text
  if (isPeerAgent) {
    return { kind: 'IGNORED', reason: 'Unstructured text from peer agent ignored' };
  }

  // 3. Human Approval Command: Check for "@devpulse approve appr_..."
  const approvalMatch = trimmed.match(APPROVAL_REGEX);
  if (approvalMatch) {
    const challengeId = approvalMatch[1]!;
    const rawSignature = approvalMatch[2] ? approvalMatch[2] : undefined;
    return {
      kind: 'APPROVAL_COMMAND',
      challengeId,
      rawSignature
    };
  }

  // 4. Incident Report / Sentinel Trigger
  // Triggers if addressed to Sentinel, or begins with @sentinel, or starts with incident keywords
  if (
    event.addressedToMe ||
    /^(?:@sentinel|inspect\b|incident:)/i.test(trimmed) ||
    trimmed.toLowerCase().includes('typeerror') ||
    trimmed.toLowerCase().includes('exception')
  ) {
    return {
      kind: 'INCIDENT_REPORT',
      text: trimmed
    };
  }

  return { kind: 'IGNORED', reason: 'Message does not match any actionable DevPulse trigger' };
}
