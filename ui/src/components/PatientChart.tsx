import React, { useState } from 'react';
import { Incident, ApprovalResult, STAGE_NAMES, LifecycleStage } from '../adapters';
import { PatchSheet } from './PatchSheet';
import { IsolationChamber } from './IsolationChamber';
import { TwoKeyApproval } from './TwoKeyApproval';

interface PatientChartProps {
  incident: Incident;
  onBack: () => void;
  onApprove: (incidentId: string) => Promise<ApprovalResult>;
  currentApprover: string;
  currentOrigin: string;
  onApproverChange: (approver: string) => void;
  onOriginChange: (origin: string) => void;
}

export const PatientChart: React.FC<PatientChartProps> = ({
  incident,
  onBack,
  onApprove,
  currentApprover,
  currentOrigin,
  onApproverChange,
  onOriginChange
}) => {
  const [isReadComplete, setIsReadComplete] = useState<boolean>(false);
  const [mobileTab, setMobileTab] = useState<'notes' | 'diff' | 'isolation'>('diff');

  const stages: LifecycleStage[] = [1, 2, 3, 4, 5, 6, 7, 8, 9];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '1440px', margin: '0 auto' }}>
      {/* Back Link & Quick Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <button
          onClick={onBack}
          style={{
            background: 'none',
            border: 'none',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            color: 'var(--ink-secondary)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 0'
          }}
        >
          &larr; Return to Ward Board
        </button>

        <span className="font-mono" style={{ fontSize: '11px', color: 'var(--ink-tertiary)' }}>
          Case File: {incident.id} // {incident.specHash.slice(0, 16)}
        </span>
      </div>

      {/* Main Physical Clipboard Container */}
      <div
        className="paper-card"
        style={{
          padding: '24px',
          background: 'var(--surface-paper-card)',
          position: 'relative',
          display: 'flex',
          flexDirection: 'column',
          gap: '20px'
        }}
      >
        {/* Metal Clipboard Clip at top */}
        <div className="clipboard-clip" />

        {/* Clipboard Header */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            borderBottom: '1px solid var(--border-paper)',
            paddingBottom: '14px',
            flexWrap: 'wrap',
            gap: '12px'
          }}
        >
          <div>
            <span
              className="font-mono"
              style={{
                fontSize: '11px',
                color: 'var(--ink-tertiary)',
                textTransform: 'uppercase',
                letterSpacing: '0.04em'
              }}
            >
              Patient Medical Chart :: {incident.id}
            </span>
            <h2
              className="font-serif"
              style={{
                fontSize: '26px',
                fontWeight: 400,
                color: 'var(--ink-primary)',
                marginTop: '2px'
              }}
            >
              {incident.title}
            </h2>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span
              className="font-mono"
              style={{
                fontSize: '11px',
                padding: '3px 8px',
                border: '1px solid var(--border-paper)',
                background: 'var(--surface-paper)',
                color: 'var(--ink-secondary)',
                borderRadius: '2px'
              }}
            >
              Admitted: {new Date(incident.admittedAt).toLocaleTimeString()}
            </span>

            <span
              className="font-mono"
              style={{
                fontSize: '11px',
                padding: '3px 8px',
                borderRadius: '2px',
                border:
                  incident.severity === 'critical'
                    ? '1px solid var(--alarm-red)'
                    : '1px solid var(--amber-pending)',
                color:
                  incident.severity === 'critical'
                    ? 'var(--alarm-red)'
                    : 'var(--amber-pending)',
                background:
                  incident.severity === 'critical'
                    ? 'var(--alarm-red-soft)'
                    : 'var(--amber-pending-soft)'
              }}
            >
              {incident.severity}
            </span>
          </div>
        </div>

        {/* 9-Stage Vitals Line */}
        <div
          style={{
            background: 'var(--surface-paper)',
            border: '1px solid var(--border-paper-light)',
            padding: '10px 16px',
            borderRadius: '2px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span
              className="font-mono"
              style={{
                fontSize: '10px',
                color: 'var(--ink-tertiary)',
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}
            >
              9-Stage Triage Lifecycle Vitals
            </span>
            <span className="font-mono" style={{ fontSize: '11px', color: 'var(--ink-primary)', fontWeight: 600 }}>
              Current: Stage {incident.stage} ({STAGE_NAMES[incident.stage]})
            </span>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              position: 'relative',
              overflowX: 'auto',
              paddingBottom: '4px'
            }}
          >
            {stages.map((stageNum, idx) => {
              const isPast = stageNum < incident.stage;
              const isCurrent = stageNum === incident.stage;
              const stageName = STAGE_NAMES[stageNum];

              let dotBg = 'var(--border-paper)';
              let dotBorder = 'var(--border-paper)';
              let textColor = 'var(--ink-tertiary)';

              if (isPast) {
                dotBg = '#2BE59A';
                dotBorder = '#189A64';
                textColor = 'var(--ink-secondary)';
              } else if (isCurrent) {
                dotBg = 'var(--amber-pending)';
                dotBorder = 'var(--brass-metal)';
                textColor = 'var(--ink-primary)';
              }

              return (
                <div
                  key={stageNum}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: '4px',
                    flex: '1 0 70px',
                    position: 'relative'
                  }}
                >
                  {/* Connecting Line */}
                  {idx > 0 && (
                    <div
                      style={{
                        position: 'absolute',
                        top: '6px',
                        right: '50%',
                        width: '100%',
                        height: '2px',
                        background: isPast ? '#2BE59A' : 'var(--border-paper-light)',
                        zIndex: 1
                      }}
                    />
                  )}

                  {/* Pulsing Dot */}
                  <div
                    style={{
                      width: '14px',
                      height: '14px',
                      borderRadius: '50%',
                      background: dotBg,
                      border: `2px solid ${dotBorder}`,
                      zIndex: 2,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      boxShadow: isCurrent ? '0 0 8px var(--amber-pending)' : 'none',
                      animation: isCurrent ? 'pulse 1.4s infinite' : 'none'
                    }}
                  >
                    {isPast && (
                      <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="#040806" strokeWidth="4">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                    )}
                  </div>

                  <span
                    className="font-mono"
                    style={{
                      fontSize: '10px',
                      fontWeight: isCurrent ? 600 : 400,
                      color: textColor,
                      whiteSpace: 'nowrap'
                    }}
                  >
                    {stageNum}. {stageName}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Mobile Segmented Tab Controls */}
        <div
          className="mobile-only-tabs"
          style={{
            display: 'none',
            borderBottom: '1px solid var(--border-paper)',
            paddingBottom: '8px',
            gap: '8px'
          }}
        >
          {(['notes', 'diff', 'isolation'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setMobileTab(tab)}
              style={{
                flex: 1,
                padding: '6px 10px',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                background: mobileTab === tab ? 'var(--ink-primary)' : 'var(--surface-paper)',
                color: mobileTab === tab ? 'var(--surface-paper-card)' : 'var(--ink-primary)',
                border: '1px solid var(--border-paper)',
                borderRadius: '2px',
                cursor: 'pointer'
              }}
            >
              {tab === 'notes' ? 'Chart Notes' : tab === 'diff' ? 'Prescription' : 'Sandbox & Sign'}
            </button>
          ))}
        </div>

        {/* 3-Column Desktop Physical Layout */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(280px, 320px) minmax(380px, 1fr) minmax(320px, 360px)',
            gap: '20px',
            alignItems: 'start'
          }}
          className="chart-columns-grid"
        >
          {/* LEFT COLUMN: Chart Notes & Stapled Prior Case File */}
          <div
            style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}
            className={`column-notes ${mobileTab === 'notes' ? 'active-mobile-col' : ''}`}
          >
            <div
              className="paper-card"
              style={{
                padding: '16px',
                background: 'var(--surface-paper)',
                border: '1px solid var(--border-paper)',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px'
              }}
            >
              <span
                className="font-mono"
                style={{
                  fontSize: '10px',
                  color: 'var(--ink-tertiary)',
                  textTransform: 'uppercase',
                  fontWeight: 600
                }}
              >
                Attending Diagnosis
              </span>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <span className="font-mono" style={{ fontSize: '11px', color: 'var(--ink-secondary)' }}>
                  Culprit Frame:
                </span>
                <span
                  className="font-mono"
                  style={{
                    fontSize: '12px',
                    fontWeight: 600,
                    color: 'var(--ink-primary)',
                    background: 'var(--surface-paper-card)',
                    padding: '4px 6px',
                    borderRadius: '2px',
                    border: '1px solid var(--border-paper-light)',
                    wordBreak: 'break-all'
                  }}
                >
                  {incident.file}:{incident.line}
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <span className="font-mono" style={{ fontSize: '11px', color: 'var(--ink-secondary)' }}>
                  Primary Error Signature:
                </span>
                <div
                  className="font-mono"
                  style={{
                    fontSize: '11px',
                    color: 'var(--alarm-red)',
                    background: 'var(--alarm-red-soft)',
                    border: '1px solid var(--alarm-red-border)',
                    padding: '6px 8px',
                    borderRadius: '2px',
                    lineHeight: '1.4'
                  }}
                >
                  {incident.errorSignature}
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <span className="font-mono" style={{ fontSize: '11px', color: 'var(--ink-secondary)' }}>
                  Etiology & Root Cause:
                </span>
                <p className="font-sans" style={{ fontSize: '12px', color: 'var(--ink-primary)', lineHeight: '1.5' }}>
                  {incident.rootCause}
                </p>
              </div>
            </div>

            {/* Stapled Prior Case File Card */}
            {incident.precedent && (
              <div
                className="paper-card"
                style={{
                  padding: '16px',
                  background: 'var(--surface-paper-lifted)',
                  border: '1px solid var(--memory-violet-border)',
                  position: 'relative',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                  transform: 'rotate(-0.5deg)'
                }}
              >
                {/* Physical Metallic Staple at top left */}
                <div
                  style={{
                    position: 'absolute',
                    top: '8px',
                    left: '12px',
                    width: '18px',
                    height: '4px',
                    background: '#6C726B',
                    borderRadius: '1px',
                    boxShadow: 'inset 0 1px 1px rgba(0,0,0,0.4), 0 1px 1px rgba(0,0,0,0.2)',
                    transform: 'rotate(25deg)'
                  }}
                />

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '6px' }}>
                  <span
                    className="font-mono"
                    style={{
                      fontSize: '10px',
                      color: 'var(--memory-violet)',
                      fontWeight: 600,
                      textTransform: 'uppercase'
                    }}
                  >
                    Stapled Precedent
                  </span>

                  <span className="stamp-verified">
                    VERIFIED // {incident.precedent.similarity}% MATCH
                  </span>
                </div>

                <div className="font-mono" style={{ fontSize: '12px', fontWeight: 600, color: 'var(--ink-primary)' }}>
                  Case #{incident.precedent.id}
                </div>

                <div style={{ fontSize: '12px', color: 'var(--ink-secondary)', lineHeight: 1.45 }}>
                  <span style={{ fontWeight: 600, color: 'var(--ink-primary)' }}>Validated Fix: </span>
                  {incident.precedent.fix}
                </div>
              </div>
            )}
          </div>

          {/* CENTER COLUMN: Patch Prescription Sheet (Diff Reader) */}
          <div
            style={{ display: 'flex', flexDirection: 'column', height: '620px' }}
            className={`column-diff ${mobileTab === 'diff' ? 'active-mobile-col' : ''}`}
          >
            <PatchSheet
              diff={incident.diff}
              file={incident.file}
              specHash={incident.specHash}
              isReadComplete={isReadComplete}
              onReadComplete={(done) => setIsReadComplete(done)}
            />
          </div>

          {/* RIGHT COLUMN: Isolation Chamber (Sandbox) + TwoKeyApproval */}
          <div
            style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}
            className={`column-isolation ${mobileTab === 'isolation' ? 'active-mobile-col' : ''}`}
          >
            <IsolationChamber
              sandbox={incident.sandbox}
              specHash={incident.specHash}
              stage={incident.stage}
            />

            <TwoKeyApproval
              incident={incident}
              isReadComplete={isReadComplete}
              onApprove={onApprove}
              currentApprover={currentApprover}
              currentOrigin={currentOrigin}
              onApproverChange={onApproverChange}
              onOriginChange={onOriginChange}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

