import React, { useState, useEffect } from 'react';
import { Incident } from '../adapters';
import { WaveformCanvas } from './WaveformCanvas';
import { STAGE_NAMES } from '../adapters/types';

interface BedProps {
  incident: Incident;
  index: number;
  isSelected: boolean;
  onSelect: () => void;
}

export const Bed: React.FC<BedProps> = ({
  incident,
  index,
  isSelected,
  onSelect
}) => {
  const [timeLeft, setTimeLeft] = useState<string>('00:00');
  const [isExpired, setIsExpired] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);

  // Live countdown timer for challenge
  useEffect(() => {
    if (!incident.challenge || incident.challenge.status !== 'open') {
      if (incident.challenge?.status === 'expired') {
        setIsExpired(true);
        setTimeLeft('00:00');
      }
      return;
    }

    const updateTimer = () => {
      const expiresAt = new Date(incident.challenge!.expiresAt).getTime();
      const diff = expiresAt - Date.now();
      if (diff <= 0) {
        setTimeLeft('00:00');
        setIsExpired(true);
      } else {
        const mins = Math.floor(diff / 60000);
        const secs = Math.floor((diff % 60000) / 1000);
        setTimeLeft(`${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`);
        setIsExpired(false);
      }
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [incident.challenge]);

  const copyHash = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(incident.specHash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 1500);
  };

  const isResolved = Boolean(incident.resolvedAt) || incident.stage === 9;
  const isRunning = incident.stage === 8;
  const isNewlyAdmitted = Date.now() - new Date(incident.admittedAt).getTime() < 120000;

  // Severity indicator color
  let statusBadgeColor = 'var(--ink-secondary)';
  let statusText = `Stage ${incident.stage}: ${STAGE_NAMES[incident.stage]}`;

  if (isExpired) {
    statusBadgeColor = 'var(--alarm-red)';
    statusText = 'Challenge expired (flatline)';
  } else if (isResolved) {
    statusBadgeColor = 'var(--ink-secondary)';
    statusText = 'Discharged / Resolved';
  } else if (isRunning) {
    statusBadgeColor = 'var(--phosphor)';
    statusText = 'Sandbox executing';
  } else if (incident.stage === 5) {
    statusBadgeColor = 'var(--amber-pending)';
    statusText = `Challenge active (${timeLeft})`;
  }

  return (
    <div
      onClick={onSelect}
      className="paper-card"
      style={{
        padding: '16px',
        cursor: 'pointer',
        border: isSelected ? '1.5px solid var(--ink-primary)' : '1px solid var(--border-paper)',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
        position: 'relative',
        minWidth: '310px',
        maxWidth: '340px',
        flex: '1 0 310px',
        background: isSelected ? 'var(--surface-paper-lifted)' : 'var(--surface-paper-card)'
      }}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect();
        }
      }}
      aria-label={`Bed ${index + 1}: ${incident.id}, ${incident.title}`}
    >
      {/* Bed Header & Patient Wristband */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span
              className="font-mono"
              style={{
                fontSize: '11px',
                color: 'var(--ink-tertiary)',
                textTransform: 'uppercase',
                letterSpacing: '0.04em'
              }}
            >
              Bed {String(index + 1).padStart(2, '0')}
            </span>
            {isNewlyAdmitted && (
              <span
                className="font-mono"
                style={{
                  fontSize: '9px',
                  padding: '1px 4px',
                  background: 'var(--amber-pending-soft)',
                  border: '1px solid var(--amber-pending)',
                  color: 'var(--amber-pending)',
                  borderRadius: '2px',
                  fontWeight: 600
                }}
              >
                NEW ADMISSION
              </span>
            )}
          </div>
          <h3
            className="font-serif"
            style={{
              fontSize: '19px',
              fontWeight: 400,
              lineHeight: 1.2,
              marginTop: '1px',
              color: 'var(--ink-primary)'
            }}
          >
            {incident.title}
          </h3>
        </div>

        <span
          className="font-mono"
          style={{
            fontSize: '10px',
            padding: '2px 6px',
            borderRadius: '2px',
            border: `1px solid ${statusBadgeColor}`,
            color: statusBadgeColor,
            whiteSpace: 'nowrap',
            backgroundColor: isExpired
              ? 'var(--alarm-red-soft)'
              : isRunning
              ? 'rgba(43, 229, 154, 0.1)'
              : incident.stage === 5
              ? 'var(--amber-pending-soft)'
              : 'transparent'
          }}
        >
          {incident.severity}
        </span>
      </div>

      {/* Patient Wristband Strip */}
      <div
        style={{
          background: 'var(--surface-paper)',
          border: '1px solid var(--border-paper-light)',
          borderRadius: '2px',
          padding: '6px 8px',
          display: 'flex',
          flexDirection: 'column',
          gap: '3px',
          fontSize: '11px'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span className="font-mono" style={{ fontWeight: 600, color: 'var(--ink-primary)' }}>
            Wristband: {incident.id}
          </span>
          <span className="font-mono" style={{ color: 'var(--ink-tertiary)', fontSize: '10px' }}>
            {new Date(incident.admittedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </span>
        </div>

        <div className="font-mono" style={{ color: 'var(--ink-secondary)', wordBreak: 'break-all' }}>
          {incident.file}:{incident.line}
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginTop: '2px',
            paddingTop: '3px',
            borderTop: '1px dashed var(--border-paper-light)'
          }}
        >
          <span className="font-mono" style={{ color: 'var(--ink-tertiary)', fontSize: '10px' }}>
            specHash: {incident.specHash.slice(0, 10)}...{incident.specHash.slice(-6)}
          </span>
          <button
            onClick={copyHash}
            style={{
              background: 'none',
              border: 'none',
              color: copiedHash ? 'var(--phosphor)' : 'var(--ink-secondary)',
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)',
              fontSize: '10px',
              padding: '1px 4px'
            }}
            title="Copy full specHash"
          >
            {copiedHash ? 'copied' : 'copy'}
          </button>
        </div>
      </div>

      {/* Live Vitals Trace Monitor (Bezel + Canvas Waveform) */}
      <div className="monitor-bezel" style={{ padding: '6px' }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '2px 6px 4px 6px',
            fontFamily: 'var(--font-mono)',
            fontSize: '10px',
            color: 'var(--phosphor)',
            opacity: 0.9
          }}
        >
          <span>VITALS // ECG</span>
          <span>{isExpired ? 'ASYSTOLE (0 BPM)' : isResolved ? '60 BPM (STABLE)' : incident.severity === 'critical' ? '142 BPM (ARRHYTHMIA)' : '88 BPM (ELEVATED)'}</span>
        </div>

        <div className="monitor-screen">
          <WaveformCanvas
            severity={incident.severity}
            isExpired={isExpired}
            isResolved={isResolved}
            height={64}
          />
        </div>
      </div>

      {/* Clinical Notes / Diagnosis Preview */}
      <div style={{ fontSize: '12px', color: 'var(--ink-secondary)', lineHeight: 1.4 }}>
        <span style={{ fontWeight: 600, color: 'var(--ink-primary)' }}>Diagnosis: </span>
        {incident.rootCause.length > 85
          ? `${incident.rootCause.slice(0, 85)}...`
          : incident.rootCause}
      </div>

      {/* Precedent Stamp (if recalled) */}
      {incident.precedent && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px' }}>
          <span className="stamp-verified">
            Precedent {incident.precedent.similarity}% match
          </span>
          <span className="font-mono" style={{ color: 'var(--ink-tertiary)' }}>
            #{incident.precedent.id}
          </span>
        </div>
      )}

      {/* Action Footer */}
      <div
        style={{
          marginTop: 'auto',
          paddingTop: '8px',
          borderTop: '1px solid var(--border-paper-light)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}
      >
        <span className="font-mono" style={{ fontSize: '11px', color: statusBadgeColor }}>
          {statusText}
        </span>

        <span
          className="font-sans"
          style={{
            fontSize: '12px',
            fontWeight: 500,
            color: 'var(--ink-primary)',
            textDecoration: isSelected ? 'underline' : 'none'
          }}
        >
          Examine chart &rarr;
        </span>
      </div>
    </div>
  );
};

