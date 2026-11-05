import React from 'react';
import { Incident } from '../adapters';
import { Bed } from './Bed';
import { StatusFilter } from '../store/useDevPulseStore';

interface WardBoardProps {
  incidents: Incident[];
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  statusFilter: StatusFilter;
  onFilterChange: (filter: StatusFilter) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onOpenIngest: () => void;
  currentApprover: string;
}

export const WardBoard: React.FC<WardBoardProps> = ({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  statusFilter,
  onFilterChange,
  searchQuery,
  onSearchChange,
  onOpenIngest,
  currentApprover
}) => {
  // Filter incidents
  const filtered = incidents.filter((incident) => {
    // 1. Status Filter
    if (statusFilter === 'needs-approval' && incident.stage !== 5) return false;
    if (statusFilter === 'running' && incident.stage !== 8) return false;
    if (statusFilter === 'resolved' && incident.stage !== 9 && !incident.resolvedAt) return false;

    // 2. Search Query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = incident.id.toLowerCase().includes(q);
      const matchTitle = incident.title.toLowerCase().includes(q);
      const matchFile = incident.file.toLowerCase().includes(q);
      const matchSig = incident.errorSignature.toLowerCase().includes(q);
      const matchHash = incident.specHash.toLowerCase().includes(q);
      return matchId || matchTitle || matchFile || matchSig || matchHash;
    }

    return true;
  });

  const countNeedsApproval = incidents.filter((i) => i.stage === 5).length;
  const countRunning = incidents.filter((i) => i.stage === 8).length;
  const countResolved = incidents.filter((i) => i.stage === 9 || Boolean(i.resolvedAt)).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
      {/* Triage Ward Attending Physician Banner */}
      <div
        className="paper-card"
        style={{
          padding: '16px 20px',
          background: 'var(--surface-paper-card)',
          border: '1px solid var(--border-paper)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '14px'
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              className="font-mono"
              style={{
                fontSize: '11px',
                color: 'var(--ink-secondary)',
                letterSpacing: '0.04em',
                textTransform: 'uppercase'
              }}
            >
              The Triage Ward // Floor 01
            </span>
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background: '#2BE59A',
                display: 'inline-block'
              }}
            />
          </div>

          <h2
            className="font-serif"
            style={{
              fontSize: '24px',
              fontWeight: 400,
              color: 'var(--ink-primary)'
            }}
          >
            Active Incident Beds
          </h2>
        </div>

        {/* Attending & Station Metadata */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '16px',
            flexWrap: 'wrap',
            fontSize: '11px',
            fontFamily: 'var(--font-mono)'
          }}
        >
          <div>
            <span style={{ color: 'var(--ink-tertiary)' }}>Attending: </span>
            <span style={{ color: 'var(--ink-primary)', fontWeight: 600 }}>{currentApprover}</span>
          </div>

          <div style={{ borderLeft: '1px solid var(--border-paper)', paddingLeft: '14px' }}>
            <span style={{ color: 'var(--ink-tertiary)' }}>Console: </span>
            <span style={{ color: 'var(--ink-primary)' }}>#incident-response-war-room</span>
          </div>

          <div style={{ borderLeft: '1px solid var(--border-paper)', paddingLeft: '14px' }}>
            <span style={{ color: 'var(--ink-tertiary)' }}>Triage Census: </span>
            <span style={{ color: 'var(--ink-primary)', fontWeight: 600 }}>
              {incidents.length} admitted
            </span>
          </div>

          <button
            onClick={onOpenIngest}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 14px',
              background: 'var(--ink-primary)',
              color: 'var(--surface-paper-card)',
              border: 'none',
              borderRadius: '2px',
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              fontWeight: 600
            }}
          >
            + Admit Stack Trace
          </button>
        </div>
      </div>

      {/* Filter Strip & Culprit Search */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px'
        }}
      >
        {/* Status Filter Buttons */}
        <div style={{ display: 'flex', gap: '6px' }}>
          {(
            [
              { id: 'all', label: `All Beds (${incidents.length})` },
              { id: 'needs-approval', label: `Needs Approval (${countNeedsApproval})` },
              { id: 'running', label: `Running Sandbox (${countRunning})` },
              { id: 'resolved', label: `Discharged (${countResolved})` }
            ] as const
          ).map((item) => (
            <button
              key={item.id}
              onClick={() => onFilterChange(item.id)}
              style={{
                padding: '5px 10px',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                background: statusFilter === item.id ? 'var(--ink-primary)' : 'var(--surface-paper-card)',
                color: statusFilter === item.id ? 'var(--surface-paper-card)' : 'var(--ink-primary)',
                border: statusFilter === item.id ? '1px solid var(--ink-primary)' : '1px solid var(--border-paper)',
                borderRadius: '2px',
                cursor: 'pointer'
              }}
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* Culprit Search Box */}
        <div style={{ display: 'flex', alignItems: 'center', minWidth: '260px' }}>
          <input
            type="text"
            placeholder="Search by file, signature, or specHash..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            style={{
              width: '100%',
              padding: '6px 10px',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              background: 'var(--surface-paper-card)',
              color: 'var(--ink-primary)',
              border: '1px solid var(--border-paper)',
              borderRadius: '2px',
              outline: 'none'
            }}
            aria-label="Filter incidents by file, signature, or hash"
          />
        </div>
      </div>

      {/* Horizontal Bed Rack (Ward Row) */}
      <div
        className="ward-beds-container"
        style={{
          display: 'flex',
          gap: '16px',
          overflowX: 'auto',
          paddingBottom: '16px',
          scrollSnapType: 'x mandatory'
        }}
      >
        {filtered.length === 0 ? (
          <div
            className="paper-card"
            style={{
              padding: '32px',
              textAlign: 'center',
              width: '100%',
              color: 'var(--ink-secondary)',
              fontFamily: 'var(--font-mono)'
            }}
          >
            No incidents match the active triage filter.
          </div>
        ) : (
          filtered.map((incident, idx) => (
            <Bed
              key={incident.id}
              incident={incident}
              index={idx}
              isSelected={selectedIncidentId === incident.id}
              onSelect={() => onSelectIncident(incident.id)}
            />
          ))
        )}
      </div>
    </div>
  );
};

