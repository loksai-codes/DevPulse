export type LifecycleStage = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;

export const STAGE_NAMES: Record<LifecycleStage, string> = {
  1: 'Detect',
  2: 'Investigate',
  3: 'Recall',
  4: 'Synthesize',
  5: 'Challenge',
  6: 'Authorize',
  7: 'Consume',
  8: 'Execute',
  9: 'Remember'
};

export interface IncidentPrecedent {
  id: string;
  similarity: number;
  fix: string;
  verified: boolean;
}

export interface IncidentChallenge {
  id: string;
  expiresAt: string; // ISO 8601
  status: 'open' | 'consumed' | 'expired';
}

export interface IncidentSandbox {
  flags: string[];
  lines: string[];
  exitCode: number | null;
  durationMs: number;
}

export interface Incident {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  file: string;
  line: number;
  errorSignature: string;
  rootCause: string;
  stage: LifecycleStage;
  precedent?: IncidentPrecedent;
  diff: string;
  specHash: string;
  challenge?: IncidentChallenge;
  sandbox?: IncidentSandbox;
  resolvedAt?: string;
  admittedAt: string;
}

export interface MemoryRecord {
  id: string;
  signature: string;
  rootCause: string;
  fix: string;
  verified: boolean;
  createdAt: string;
  similarity?: number;
}

export interface AuditEntry {
  seq: number;
  ts: string;
  event: string;
  detail: Record<string, unknown> | string;
  prevHash: string;
  hash: string;
  tampered?: boolean;
}

export interface ApprovalRequest {
  challengeId: string;
  approverId: string;
  origin: string;
  specHash?: string;
}

export type ApprovalRejectionCode =
  | 'NOT_ON_ALLOWLIST'
  | 'BRIDGED_ORIGIN'
  | 'EXPIRED_TTL'
  | 'REPLAY_ATTACK'
  | 'HASH_MISMATCH';

export type ApprovalResult =
  | { accepted: true; executionId: string }
  | { accepted: false; reason: string; code: ApprovalRejectionCode };

export interface DevPulseAdapter {
  getIncidents(): Promise<Incident[]>;
  getMemoryRecords(): Promise<MemoryRecord[]>;
  getAuditEntries(): Promise<AuditEntry[]>;
  ingestTrace(traceText: string): Promise<Incident>;
  submitApproval(req: ApprovalRequest): Promise<ApprovalResult>;
  runSandbox(incidentId: string, onLine: (line: string) => void): Promise<{ exitCode: number; durationMs: number }>;
  recordMemory(record: Omit<MemoryRecord, 'id' | 'createdAt'>): Promise<MemoryRecord>;
  verifyAuditChain(entries: AuditEntry[]): Promise<{ valid: boolean; brokenSeq?: number; reason?: string }>;
}

