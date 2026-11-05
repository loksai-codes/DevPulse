import React, { useRef, useState, useEffect } from 'react';

interface PatchSheetProps {
  diff: string;
  file: string;
  specHash: string;
  onReadComplete: (completed: boolean) => void;
  isReadComplete: boolean;
}

export const PatchSheet: React.FC<PatchSheetProps> = ({
  diff,
  file,
  specHash,
  onReadComplete,
  isReadComplete
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [readPercent, setReadPercent] = useState<number>(0);

  // Parse lines for line counting and unified syntax tinting
  const lines = diff.split('\n');
  const additions = lines.filter((l) => l.startsWith('+') && !l.startsWith('+++')).length;
  const deletions = lines.filter((l) => l.startsWith('-') && !l.startsWith('---')).length;

  const handleScroll = () => {
    const el = containerRef.current;
    if (!el) return;
    const { scrollTop, scrollHeight, clientHeight } = el;
    const maxScroll = scrollHeight - clientHeight;

    if (maxScroll <= 5) {
      // Content fits without scrolling -> automatically 100%
      setReadPercent(100);
      onReadComplete(true);
      return;
    }

    const currentPercent = Math.min(100, Math.round(((scrollTop + clientHeight) / scrollHeight) * 100));
    setReadPercent(currentPercent);

    if (currentPercent >= 98 && !isReadComplete) {
      onReadComplete(true);
    }
  };

  useEffect(() => {
    // Check initial scroll height
    handleScroll();
  }, [diff]);

  return (
    <div
      className="paper-card"
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        background: 'var(--surface-paper-card)',
        border: '1px solid var(--border-paper)',
        overflow: 'hidden'
      }}
    >
      {/* Prescription Header */}
      <div
        style={{
          padding: '14px 18px',
          borderBottom: '1px solid var(--border-paper)',
          background: 'var(--surface-paper)',
          display: 'flex',
          flexDirection: 'column',
          gap: '6px'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
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
            Prescription Order :: Proposed Patch
          </span>

          <span className="font-mono" style={{ fontSize: '11px', color: 'var(--ink-secondary)' }}>
            <span style={{ color: '#1B8A5A', fontWeight: 600 }}>+{additions}</span>{' '}
            <span style={{ color: 'var(--alarm-red)', fontWeight: 600 }}>-{deletions}</span> lines
          </span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: '8px' }}>
          <span className="font-mono" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--ink-primary)' }}>
            Target: {file}
          </span>

          <span className="font-mono" style={{ fontSize: '10px', color: 'var(--ink-tertiary)' }}>
            specHash: {specHash.slice(0, 16)}...{specHash.slice(-8)}
          </span>
        </div>
      </div>

      {/* Read Tracking Bar */}
      <div
        style={{
          padding: '6px 18px',
          background: isReadComplete ? 'rgba(43, 229, 154, 0.12)' : 'var(--amber-pending-soft)',
          borderBottom: '1px solid var(--border-paper-light)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '11px',
          fontFamily: 'var(--font-mono)'
        }}
        aria-live="polite"
      >
        <span style={{ color: isReadComplete ? '#14633E' : 'var(--brass-metal-dark)', fontWeight: 600 }}>
          {isReadComplete
            ? '✓ Prescription fully read & verified (100%) - Key turn unlocked'
            : `Prescription unread (${readPercent}%) - Scroll to bottom to verify`}
        </span>

        {/* Physical Progress Gauge */}
        <div
          style={{
            width: '80px',
            height: '6px',
            background: 'var(--surface-paper)',
            borderRadius: '2px',
            border: '1px solid var(--border-paper)',
            overflow: 'hidden'
          }}
        >
          <div
            style={{
              width: `${readPercent}%`,
              height: '100%',
              background: isReadComplete ? '#249E6B' : 'var(--amber-pending)',
              transition: 'width 0.1s ease-out'
            }}
          />
        </div>
      </div>

      {/* Unified Diff Content with Line Numbers & Syntax Tint */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '12px 0',
          fontFamily: 'var(--font-mono)',
          fontSize: '12px',
          lineHeight: '1.6',
          backgroundColor: 'var(--surface-paper-lifted)'
        }}
        tabIndex={0}
        aria-label="Prescription diff content. Scroll to read."
      >
        {lines.map((line, idx) => {
          let bg = 'transparent';
          let textColor = 'var(--ink-primary)';
          let prefix = ' ';

          if (line.startsWith('+++') || line.startsWith('---')) {
            textColor = 'var(--ink-tertiary)';
            bg = 'rgba(0,0,0,0.02)';
          } else if (line.startsWith('@@')) {
            textColor = 'var(--memory-violet)';
            bg = 'var(--memory-violet-soft)';
          } else if (line.startsWith('+')) {
            textColor = '#0F613B';
            bg = 'rgba(43, 229, 154, 0.15)';
            prefix = '+';
          } else if (line.startsWith('-')) {
            textColor = '#B3261E';
            bg = 'rgba(229, 53, 43, 0.12)';
            prefix = '-';
          }

          return (
            <div
              key={idx}
              style={{
                display: 'flex',
                padding: '1px 16px',
                background: bg,
                color: textColor,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all'
              }}
            >
              <span
                style={{
                  width: '36px',
                  userSelect: 'none',
                  color: 'var(--ink-tertiary)',
                  textAlign: 'right',
                  paddingRight: '12px',
                  opacity: 0.6
                }}
              >
                {idx + 1}
              </span>
              <span style={{ flex: 1 }}>{line}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

