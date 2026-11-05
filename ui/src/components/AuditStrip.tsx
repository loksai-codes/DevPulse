import React, { useState } from 'react';
import { AuditEntry } from '../adapters';

interface AuditStripProps {
  entries: AuditEntry[];
  tamperedSeq: number | null;
  onTamper: (seq: number) => void;
  onRestore: () => void;
  onVerify: () => Promise<void>;
  isVerifying: boolean;
  verificationResult: { valid: boolean; brokenSeq?: number; reason?: string } | null;
}

export const AuditStrip: React.FC<AuditStripProps> = ({
  entries,
  tamperedSeq,
  onTamper,
  onRestore,
  onVerify,
  isVerifying,
  verificationResult
}) => {
  const [copiedSeq, setCopiedSeq] = useState<number | null>(null);

  const copyHash = (hash: string, seq: number) => {
    navigator.clipboard.writeText(hash);
    setCopiedSeq(seq);
    setTimeout(() => setCopiedSeq(null), 1200);
  };

  const isTampered = tamperedSeq !== null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '18px', maxWidth: '1280px', margin: '0 auto' }}>
      {/* Strip Control Header */}
      <div
        className="paper-card"
        style={{
          padding: '18px 24px',
          background: 'var(--surface-paper-card)',
          border: '1px solid var(--border-paper)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px'
        }}
      >
        <div>
          <span
            className="font-mono"
            style={{
              fontSize: '11px',
              color: 'var(--ink-secondary)',
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              fontWeight: 600
            }}
          >
            Cryptographic Strip Chart :: Continuous Hash Chain
          </span>
          <h2
            className="font-serif"
            style={{
              fontSize: '24px',
              fontWeight: 400,
              color: 'var(--ink-primary)',
              marginTop: '2px'
            }}
          >
            Immutable Audit Trail
          </h2>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            onClick={onVerify}
            disabled={isVerifying}
            style={{
              padding: '7px 14px',
              background: 'var(--ink-primary)',
              color: 'var(--surface-paper-card)',
              border: 'none',
              borderRadius: '2px',
              cursor: isVerifying ? 'wait' : 'pointer',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            {isVerifying ? 'Scanning Chain...' : 'Sweep Verify Chain (Web Crypto)'}
          </button>

          {!isTampered ? (
            <button
              onClick={() => onTamper(2)}
              style={{
                padding: '7px 14px',
                background: 'var(--alarm-red-soft)',
                color: 'var(--alarm-red)',
                border: '1px solid var(--alarm-red-border)',
                borderRadius: '2px',
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                fontWeight: 600
              }}
            >
              Simulate Tamper on Seq #02
            </button>
          ) : (
            <button
              onClick={onRestore}
              style={{
                padding: '7px 14px',
                background: 'rgba(43, 229, 154, 0.15)',
                color: '#137547',
                border: '1px solid #137547',
                borderRadius: '2px',
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                fontWeight: 600
              }}
            >
              Restore Authentic Chain
            </button>
          )}
        </div>
      </div>

      {/* Verification Status Banner */}
      {verificationResult && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: '2px',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: verificationResult.valid ? 'rgba(43, 229, 154, 0.12)' : 'var(--alarm-red-soft)',
            border: `1px solid ${verificationResult.valid ? '#1DBE78' : 'var(--alarm-red)'}`,
            color: verificationResult.valid ? '#0D683D' : 'var(--alarm-red)'
          }}
          role="alert"
        >
          <span>
            {verificationResult.valid
              ? `✓ Hash chain verification successful: All ${entries.length} sequences cryptographically intact.`
              : `⚠ Hash chain verification failed: ${verificationResult.reason}`}
          </span>
          <span>Web Crypto SHA-256</span>
        </div>
      )}

      {/* Continuous Paper Strip Container */}
      <div
        className="paper-card ecg-grid-bg"
        style={{
          border: '1px solid var(--border-paper)',
          padding: '24px 0',
          position: 'relative',
          overflowX: 'auto',
          boxShadow: 'var(--shadow-paper)'
        }}
      >
        {/* Verification Sweep Animation Laser Line */}
        {isVerifying && (
          <div
            style={{
              position: 'absolute',
              top: 0,
              bottom: 0,
              width: '3px',
              background: '#2BE59A',
              boxShadow: '0 0 12px #2BE59A, 0 0 24px #2BE59A',
              zIndex: 20,
              animation: 'sweep 0.6s ease-in-out infinite alternate'
            }}
          />
        )}

        {/* Paper Perforation Ticks along Top */}
        <div
          style={{
            height: '8px',
            backgroundImage: 'radial-gradient(circle, var(--ink-tertiary) 1.5px, transparent 1.5px)',
            backgroundSize: '16px 8px',
            opacity: 0.4,
            marginBottom: '16px'
          }}
        />

        {/* Event Ticks Along Continuous Chain */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0px', padding: '0 24px' }}>
          {entries.map((entry, idx) => {
            const isEntryTampered = isTampered && tamperedSeq !== null && entry.seq >= tamperedSeq;
            const isTearPoint = isTampered && entry.seq === tamperedSeq;

            const tickColor = isEntryTampered ? 'var(--alarm-red)' : 'var(--ink-primary)';
            const borderTint = isEntryTampered ? 'var(--alarm-red-border)' : 'var(--border-paper)';
            const bgTint = isEntryTampered ? 'var(--alarm-red-soft)' : 'var(--surface-paper-card)';

            return (
              <React.Fragment key={entry.seq}>
                {/* Physical Jagged Paper Tear Marker */}
                {isTearPoint && (
                  <div
                    style={{
                      margin: '12px 0',
                      position: 'relative',
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center'
                    }}
                  >
                    <svg width="100%" height="24" preserveAspectRatio="none" viewBox="0 0 1000 24">
                      <path
                        d="M0,12 L30,4 L60,20 L90,6 L130,18 L170,3 L210,21 L260,8 L310,19 L360,5 L420,20 L480,7 L540,19 L600,6 L660,18 L720,4 L780,20 L840,7 L900,19 L950,5 L1000,12"
                        fill="none"
                        stroke="var(--alarm-red)"
                        strokeWidth="2.5"
                        strokeDasharray="4 2"
                      />
                    </svg>
                    <div
                      style={{
                        background: 'var(--alarm-red)',
                        color: '#FFFFFF',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11px',
                        padding: '3px 10px',
                        borderRadius: '2px',
                        fontWeight: 600,
                        marginTop: '-12px'
                      }}
                    >
                      ⚠ CRYPTOGRAPHIC CHAIN SEVERED HERE: SEQ #{String(entry.seq).padStart(2, '0')}
                    </div>
                  </div>
                )}

                {/* Audit Tick Card */}
                <div
                  style={{
                    display: 'flex',
                    gap: '16px',
                    position: 'relative',
                    paddingBottom: idx === entries.length - 1 ? '0' : '20px'
                  }}
                >
                  {/* Left Hash Chain Line with Node */}
                  <div
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      width: '32px',
                      flexShrink: 0
                    }}
                  >
                    <div
                      style={{
                        width: '14px',
                        height: '14px',
                        borderRadius: '50%',
                        border: `2px solid ${tickColor}`,
                        background: isEntryTampered ? 'var(--alarm-red)' : 'var(--surface-paper-lifted)',
                        boxShadow: isEntryTampered ? '0 0 8px var(--alarm-red)' : 'none',
                        zIndex: 2
                      }}
                    />

                    {idx < entries.length - 1 && (
                      <div
                        style={{
                          width: '2px',
                          flex: 1,
                          background: isEntryTampered ? 'var(--alarm-red)' : 'var(--border-paper)',
                          zIndex: 1,
                          marginTop: '2px'
                        }}
                      />
                    )}
                  </div>

                  {/* Audit Event Entry Box */}
                  <div
                    className="paper-card"
                    style={{
                      flex: 1,
                      padding: '12px 16px',
                      background: bgTint,
                      border: `1px solid ${borderTint}`,
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px'
                    }}
                  >
                    {/* Event Header */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span
                          className="font-mono"
                          style={{
                            fontSize: '12px',
                            fontWeight: 600,
                            color: tickColor
                          }}
                        >
                          Seq #{String(entry.seq).padStart(2, '0')} :: {entry.event}
                        </span>

                        {isEntryTampered && (
                          <span
                            className="font-mono"
                            style={{
                              fontSize: '10px',
                              padding: '1px 5px',
                              background: 'var(--alarm-red)',
                              color: '#FFFFFF',
                              borderRadius: '2px',
                              fontWeight: 600
                            }}
                          >
                            INVALID HASH
                          </span>
                        )}
                      </div>

                      <span className="font-mono" style={{ fontSize: '11px', color: 'var(--ink-tertiary)' }}>
                        {entry.ts}
                      </span>
                    </div>

                    {/* Hash Pointers (prevHash -> hash) */}
                    <div
                      style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                        gap: '8px',
                        background: 'var(--surface-paper)',
                        padding: '6px 10px',
                        borderRadius: '2px',
                        fontSize: '11px',
                        fontFamily: 'var(--font-mono)'
                      }}
                    >
                      <div>
                        <span style={{ color: 'var(--ink-tertiary)' }}>prevHash: </span>
                        <span style={{ color: 'var(--ink-secondary)' }}>
                          {entry.prevHash.slice(0, 16)}...{entry.prevHash.slice(-8)}
                        </span>
                      </div>

                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                          <span style={{ color: 'var(--ink-tertiary)' }}>hash: </span>
                          <span style={{ color: tickColor, fontWeight: 600 }}>
                            {entry.hash.slice(0, 16)}...{entry.hash.slice(-8)}
                          </span>
                        </div>
                        <button
                          onClick={() => copyHash(entry.hash, entry.seq)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: copiedSeq === entry.seq ? 'var(--phosphor)' : 'var(--ink-tertiary)',
                            cursor: 'pointer',
                            fontSize: '10px',
                            fontFamily: 'var(--font-mono)'
                          }}
                        >
                          {copiedSeq === entry.seq ? 'copied' : 'copy'}
                        </button>
                      </div>
                    </div>

                    {/* Detail Payload JSON */}
                    <pre
                      className="font-mono"
                      style={{
                        fontSize: '11px',
                        color: 'var(--ink-primary)',
                        background: 'var(--surface-paper-lifted)',
                        padding: '6px 10px',
                        borderRadius: '2px',
                        border: '1px solid var(--border-paper-light)',
                        overflowX: 'auto',
                        whiteSpace: 'pre-wrap'
                      }}
                    >
                      {typeof entry.detail === 'object'
                        ? JSON.stringify(entry.detail, null, 2)
                        : String(entry.detail)}
                    </pre>
                  </div>
                </div>
              </React.Fragment>
            );
          })}
        </div>

        {/* Paper Perforation Ticks along Bottom */}
        <div
          style={{
            height: '8px',
            backgroundImage: 'radial-gradient(circle, var(--ink-tertiary) 1.5px, transparent 1.5px)',
            backgroundSize: '16px 8px',
            opacity: 0.4,
            marginTop: '16px'
          }}
        />
      </div>
    </div>
  );
};

