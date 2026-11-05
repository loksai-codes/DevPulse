import React, { useRef, useEffect } from 'react';
import { IncidentSandbox } from '../adapters';

interface IsolationChamberProps {
  sandbox?: IncidentSandbox;
  specHash: string;
  stage: number;
}

export const IsolationChamber: React.FC<IsolationChamberProps> = ({
  sandbox,
  specHash,
  stage
}) => {
  const terminalRef = useRef<HTMLDivElement | null>(null);

  // Auto scroll terminal when lines arrive
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [sandbox?.lines]);

  const flags = sandbox?.flags || ['--network none', 'read-only rootfs', 'non-root: sandbox_user'];
  const lines = sandbox?.lines || [
    '[SANDBOX INIT] Mounting isolated container overlay...',
    '[SANDBOX INIT] Non-root uid 10001 (sandbox_user) active.',
    '[SANDBOX INIT] Network unshared (--network none).',
    '[READY] Sealed and standing by for maintainer authorization.'
  ];

  const isExecuted = sandbox?.exitCode !== null && sandbox?.exitCode !== undefined;
  const isPass = sandbox?.exitCode === 0;

  return (
    <div className="monitor-bezel" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {/* Hardware Control Header & Indicator Lamps */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '6px',
          padding: '2px 4px 6px 4px',
          borderBottom: '1px solid #1C2720'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span
            className="font-mono"
            style={{
              fontSize: '10px',
              color: 'var(--phosphor)',
              letterSpacing: '0.06em',
              fontWeight: 600,
              textTransform: 'uppercase'
            }}
          >
            Isolation Chamber :: Runner Docker Sandbox
          </span>

          <span
            className="font-mono"
            style={{
              fontSize: '10px',
              color: isExecuted ? (isPass ? 'var(--phosphor)' : 'var(--alarm-red)') : '#8BA193'
            }}
          >
            {isExecuted
              ? isPass
                ? `PASSED (${sandbox?.durationMs}ms)`
                : `FAILED (Exit ${sandbox?.exitCode})`
              : stage === 8
              ? 'EXECUTING...'
              : 'SEALED // IDLE'}
          </span>
        </div>

        {/* Hardware Indicator Lamps */}
        <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
          {flags.map((flag, idx) => (
            <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <span
                style={{
                  width: '7px',
                  height: '7px',
                  borderRadius: '50%',
                  background: 'var(--phosphor)',
                  boxShadow: '0 0 6px var(--phosphor)',
                  display: 'inline-block'
                }}
              />
              <span
                className="font-mono"
                style={{
                  fontSize: '10px',
                  color: '#9EBAA9',
                  letterSpacing: '0.02em'
                }}
              >
                {flag}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Recessed CRT Screen with Phosphor Terminal Stream */}
      <div
        className="monitor-screen"
        style={{
          height: '240px',
          display: 'flex',
          flexDirection: 'column',
          position: 'relative'
        }}
      >
        <div
          ref={terminalRef}
          style={{
            flex: 1,
            overflowY: 'auto',
            padding: '10px 14px',
            fontSize: '11px',
            lineHeight: '1.55',
            color: 'var(--phosphor)',
            fontFamily: 'var(--font-mono)'
          }}
          tabIndex={0}
          aria-label="Sandbox terminal stream"
        >
          {lines.map((line, idx) => {
            const isSuccess = line.includes('✔') || line.includes('PASS') || line.includes('passed');
            const isErr = line.includes('FAIL') || line.includes('Error');
            return (
              <div
                key={idx}
                style={{
                  color: isSuccess ? '#4EFAAC' : isErr ? '#FF6B61' : 'var(--phosphor)',
                  opacity: 0.95
                }}
              >
                {line}
              </div>
            );
          })}
          {stage === 8 && (
            <span style={{ display: 'inline-block', animation: 'blink 1s infinite' }}>
              █
            </span>
          )}
        </div>

        {/* Terminal Status Footer */}
        <div
          style={{
            borderTop: '1px solid rgba(43, 229, 154, 0.15)',
            padding: '4px 14px',
            fontSize: '10px',
            color: 'rgba(43, 229, 154, 0.7)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: 'rgba(0,0,0,0.4)',
            zIndex: 3
          }}
        >
          <span>SPEC: {specHash.slice(0, 12)}...</span>
          <span>NET: NONE // RO: ROOTFS</span>
        </div>
      </div>

      {/* Pass/Fail Evidence Summary Card */}
      {isExecuted && (
        <div
          style={{
            background: isPass ? 'rgba(43, 229, 154, 0.08)' : 'rgba(240, 69, 59, 0.12)',
            border: `1px solid ${isPass ? 'rgba(43, 229, 154, 0.3)' : 'rgba(240, 69, 59, 0.35)'}`,
            borderRadius: '4px',
            padding: '8px 12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '3px'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span
              className="font-mono"
              style={{
                fontSize: '11px',
                fontWeight: 600,
                color: isPass ? 'var(--phosphor)' : 'var(--alarm-red)'
              }}
            >
              {isPass ? 'EVIDENCE: ALL REGRESSION TESTS PASSED' : 'EVIDENCE: REGRESSION DETECTED'}
            </span>
            <span className="font-mono" style={{ fontSize: '10px', color: '#9EBAA9' }}>
              Exit {sandbox?.exitCode} in {sandbox?.durationMs}ms
            </span>
          </div>
          <span className="font-sans" style={{ fontSize: '11px', color: '#9EBAA9' }}>
            Applied inside sealed container with zero network egress. Patch verified without side effects.
          </span>
        </div>
      )}
    </div>
  );
};

