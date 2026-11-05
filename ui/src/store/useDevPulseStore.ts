import { create } from 'zustand';
import {
  Incident,
  MemoryRecord,
  AuditEntry,
  ApprovalResult,
  getAdapter,
  setAdapterMode,
  getAdapterMode,
  ALLOWED_MAINTAINERS,
  AUTHORIZED_SWITCH_ORIGIN
} from '../adapters';

export type StatusFilter = 'all' | 'needs-approval' | 'running' | 'resolved';
export type AppTab = 'ward' | 'records' | 'strip';
export type ThemeMode = 'daylight' | 'nightshift';
export type SecurityOverride =
  | 'none'
  | 'unauthorized_user'
  | 'slack_bridge'
  | 'expired_ttl'
  | 'replay_attack'
  | 'spec_tamper';

interface DevPulseState {
  incidents: Incident[];
  selectedIncidentId: string | null;
  statusFilter: StatusFilter;
  searchQuery: string;
  activeTab: AppTab;
  theme: ThemeMode;
  adapterMode: 'mock' | 'live';
  isIngestOpen: boolean;
  memoryRecords: MemoryRecord[];
  auditEntries: AuditEntry[];

  // Security test controls
  currentApprover: string;
  currentOrigin: string;
  securityOverride: SecurityOverride;
  lastApprovalResult: ApprovalResult | null;
  isApprovalRunning: boolean;

  // Audit chain states
  tamperedSeq: number | null;
  isVerifyingChain: boolean;
  chainVerificationResult: { valid: boolean; brokenSeq?: number; reason?: string } | null;

  // Actions
  init: () => Promise<void>;
  selectIncident: (id: string | null) => void;
  setStatusFilter: (filter: StatusFilter) => void;
  setSearchQuery: (q: string) => void;
  setActiveTab: (tab: AppTab) => void;
  toggleTheme: () => void;
  toggleAdapterMode: () => Promise<void>;
  setIngestOpen: (open: boolean) => void;
  setCurrentApprover: (id: string) => void;
  setCurrentOrigin: (origin: string) => void;
  setSecurityOverride: (override: SecurityOverride) => void;
  ingestTrace: (trace: string) => Promise<Incident>;
  submitTwoKeyApproval: (incidentId: string) => Promise<ApprovalResult>;
  runSandboxExecution: (incidentId: string) => Promise<void>;
  tamperAuditEntry: (seq: number) => void;
  restoreAuditChain: () => Promise<void>;
  verifyAuditChain: () => Promise<void>;
}

const savedTheme = (typeof window !== 'undefined' && localStorage.getItem('devpulse_theme') as ThemeMode) || 'daylight';

export const useDevPulseStore = create<DevPulseState>((set, get) => ({
  incidents: [],
  selectedIncidentId: null, // Start on Ward Board overview
  statusFilter: 'all',
  searchQuery: '',
  activeTab: 'ward',
  theme: savedTheme,
  adapterMode: getAdapterMode(),
  isIngestOpen: false,
  memoryRecords: [],
  auditEntries: [],

  currentApprover: ALLOWED_MAINTAINERS[0] || 'dr_sarah_lin',
  currentOrigin: AUTHORIZED_SWITCH_ORIGIN,
  securityOverride: 'none',
  lastApprovalResult: null,
  isApprovalRunning: false,

  tamperedSeq: null,
  isVerifyingChain: false,
  chainVerificationResult: null,

  init: async () => {
    const adapter = getAdapter();
    const [incidents, memoryRecords, auditEntries] = await Promise.all([
      adapter.getIncidents(),
      adapter.getMemoryRecords(),
      adapter.getAuditEntries()
    ]);
    set({
      incidents,
      memoryRecords,
      auditEntries,
      selectedIncidentId: null // Overview screen is the ward board
    });
  },

  selectIncident: (id) => set({ selectedIncidentId: id }),

  setStatusFilter: (filter) => set({ statusFilter: filter }),

  setSearchQuery: (q) => set({ searchQuery: q }),

  setActiveTab: (tab) => set({ activeTab: tab }),

  toggleTheme: () => {
    const next: ThemeMode = get().theme === 'daylight' ? 'nightshift' : 'daylight';
    if (typeof window !== 'undefined') {
      localStorage.setItem('devpulse_theme', next);
    }
    set({ theme: next });
  },

  toggleAdapterMode: async () => {
    const nextMode = get().adapterMode === 'mock' ? 'live' : 'mock';
    const adapter = setAdapterMode(nextMode);
    const [incidents, memoryRecords, auditEntries] = await Promise.all([
      adapter.getIncidents(),
      adapter.getMemoryRecords(),
      adapter.getAuditEntries()
    ]);
    set({
      adapterMode: nextMode,
      incidents,
      memoryRecords,
      auditEntries,
      selectedIncidentId: null
    });
  },

  setIngestOpen: (open) => set({ isIngestOpen: open }),

  setCurrentApprover: (id) => set({ currentApprover: id }),

  setCurrentOrigin: (origin) => set({ currentOrigin: origin }),

  setSecurityOverride: (override) => {
    set({ securityOverride: override });
    if (override === 'unauthorized_user') {
      set({ currentApprover: 'intern_guest_read_only' });
    } else if (override === 'slack_bridge') {
      set({ currentOrigin: 'slack_webhook_bridge' });
    } else if (override === 'none') {
      set({
        currentApprover: ALLOWED_MAINTAINERS[0] || 'dr_sarah_lin',
        currentOrigin: AUTHORIZED_SWITCH_ORIGIN
      });
    }
  },

  ingestTrace: async (trace: string) => {
    const adapter = getAdapter();
    const incident = await adapter.ingestTrace(trace);
    const [incidents, auditEntries] = await Promise.all([
      adapter.getIncidents(),
      adapter.getAuditEntries()
    ]);
    set({
      incidents,
      auditEntries,
      selectedIncidentId: null, // Return to Ward Board so the user sees the new bed appear!
      statusFilter: 'all', // Clear filter so the new bed is immediately visible
      searchQuery: '',
      isIngestOpen: false,
      activeTab: 'ward'
    });
    return incident;
  },

  submitTwoKeyApproval: async (incidentId: string) => {
    const { currentApprover, currentOrigin, securityOverride, incidents } = get();
    const incident = incidents.find((i) => i.id === incidentId);
    if (!incident || !incident.challenge) {
      return {
        accepted: false,
        reason: 'No active challenge found for incident.',
        code: 'EXPIRED_TTL'
      };
    }

    set({ isApprovalRunning: true, lastApprovalResult: null });

    // Handle security override states
    let approver = currentApprover;
    let origin = currentOrigin;
    let specHash = incident.specHash;

    if (securityOverride === 'unauthorized_user') {
      approver = 'intern_guest_read_only';
    } else if (securityOverride === 'slack_bridge') {
      origin = 'slack_webhook_bridge';
    } else if (securityOverride === 'spec_tamper') {
      specHash = '0000000000000000000000000000000000000000000000000000000000000000';
    }

    const adapter = getAdapter();
    const result = await adapter.submitApproval({
      challengeId: incident.challenge.id,
      approverId: approver,
      origin,
      specHash
    });

    const [updatedIncidents, auditEntries] = await Promise.all([
      adapter.getIncidents(),
      adapter.getAuditEntries()
    ]);

    set({
      lastApprovalResult: result,
      incidents: updatedIncidents,
      auditEntries,
      isApprovalRunning: false
    });

    if (result.accepted) {
      // Trigger runner sandbox execution
      get().runSandboxExecution(incidentId);
    }

    return result;
  },

  runSandboxExecution: async (incidentId: string) => {
    const adapter = getAdapter();
    const onLine = (line: string) => {
      set((state) => ({
        incidents: state.incidents.map((inc) => {
          if (inc.id === incidentId && inc.sandbox) {
            return {
              ...inc,
              sandbox: {
                ...inc.sandbox,
                lines: [...inc.sandbox.lines, line]
              }
            };
          }
          return inc;
        })
      }));
    };

    await adapter.runSandbox(incidentId, onLine);

    const [incidents, memoryRecords, auditEntries] = await Promise.all([
      adapter.getIncidents(),
      adapter.getMemoryRecords(),
      adapter.getAuditEntries()
    ]);

    set({ incidents, memoryRecords, auditEntries });
  },

  tamperAuditEntry: (seq: number) => {
    set((state) => {
      const tamperedEntries = state.auditEntries.map((e) => {
        if (e.seq === seq) {
          return {
            ...e,
            tampered: true,
            detail: {
              ...((typeof e.detail === 'object' && e.detail !== null ? e.detail : { original: e.detail }) as object),
              _TAMPERED: 'Malicious modification injected by unauthorized process.'
            }
          };
        }
        return e;
      });
      return {
        auditEntries: tamperedEntries,
        tamperedSeq: seq,
        chainVerificationResult: {
          valid: false,
          brokenSeq: seq,
          reason: `Cryptographic digest mismatch at seq ${seq}. Entry contents were altered.`
        }
      };
    });
  },

  restoreAuditChain: async () => {
    const adapter = getAdapter();
    const entries = await adapter.getAuditEntries();
    set({
      auditEntries: entries,
      tamperedSeq: null,
      chainVerificationResult: null
    });
  },

  verifyAuditChain: async () => {
    set({ isVerifyingChain: true, chainVerificationResult: null });
    // Smooth verification sweep delay for clinical strip scanning effect
    await new Promise((res) => setTimeout(res, 600));
    const adapter = getAdapter();
    const result = await adapter.verifyAuditChain(get().auditEntries);
    set({
      isVerifyingChain: false,
      chainVerificationResult: result
    });
  }
}));
