import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface IngestDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  onIngest: (trace: string) => Promise<void>;
}

const PRESETS = [
  {
    title: 'Auth null deref',
    trace: `TypeError: Cannot read properties of null (reading 'sub')
    at SessionVerifier.verifyToken (/workspace/devpulse/src/auth/session-verifier.ts:142:25)
    at async AuthMiddleware.handleRequest (/workspace/devpulse/src/auth/middleware.ts:48:20)
    at async Router.dispatch (/workspace/devpulse/src/router/event-router.ts:89:12)`
  },
  {
    title: 'Queue worker spin',
    trace: `RangeError: Maximum call stack size exceeded
    at WorkerDispatcher.pollNextBatch (/workspace/devpulse/src/queue/worker-dispatcher.ts:88:14)
    at WorkerDispatcher.pollNextBatch (/workspace/devpulse/src/queue/worker-dispatcher.ts:92:12)
    at async WorkerDispatcher.start (/workspace/devpulse/src/queue/worker-dispatcher.ts:35:5)`
  },
  {
    title: 'Config loader crash',
    trace: `Error: DEVPULSE_APPROVAL_SECRET environment variable is missing. Refusing to run with insecure default secret.
    at getApprovalSecret (/workspace/devpulse/src/config/env-loader.ts:31:11)
    at Gatekeeper.init (/workspace/devpulse/src/gate/index.ts:54:22)
    at async main (/workspace/devpulse/src/gate/index.ts:120:3)`
  }
];

export const IngestDrawer: React.FC<IngestDrawerProps> = ({
  isOpen,
  onClose,
  onIngest
}) => {
  const [traceText, setTraceText] = useState<string>(PRESETS[0]!.trace);
  const [isIngesting, setIsIngesting] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Sentinel preview parse
  const parsedFile = traceText.includes('session-verifier')
    ? 'src/auth/session-verifier.ts:142'
    : traceText.includes('worker-dispatcher')
    ? 'src/queue/worker-dispatcher.ts:88'
    : traceText.includes('env-loader')
    ? 'src/config/env-loader.ts:31'
    : 'src/service/worker.ts:42';

  const matchedPrecedent = traceText.includes('session-verifier')
    ? 'REC-7210 (94% match) - Defensive null check on expired session'
    : traceText.includes('worker-dispatcher')
    ? 'REC-6114 (88% match) - Insert jittered backoff on empty dequeue'
    : 'REC-5890 (78% match) - Development fallback secret validator';

  const handleExecuteIngest = async (e?: React.FormEvent | React.MouseEvent) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    if (!traceText.trim() || isIngesting) return;

    setErrorMsg(null);
    setSuccessMsg(null);
    setIsIngesting(true);

    try {
      await onIngest(traceText);
      setSuccessMsg('Patient admitted! Displaying on Ward Board...');
      setTimeout(() => {
        setIsIngesting(false);
        setSuccessMsg(null);
        onClose();
      }, 350);
    } catch (err: unknown) {
      console.error('Ingest error:', err);
      const msg = err instanceof Error ? err.message : String(err);
      setErrorMsg(`Admission failed: ${msg}`);
      setIsIngesting(false);
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: 'rgba(20, 32, 26, 0.45)',
              zIndex: 100,
              backdropFilter: 'blur(2px)'
            }}
          />

          {/* Drawer Panel */}
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 26, stiffness: 240 }}
            style={{
              position: 'fixed',
              top: 0,
              right: 0,
              bottom: 0,
              width: 'min(580px, 100vw)',
              background: 'var(--surface-paper-card)',
              borderLeft: '1px solid var(--border-paper)',
              zIndex: 101,
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '-4px 0 24px rgba(20, 32, 26, 0.2)'
            }}
          >
            {/* Drawer Header */}
            <div
              style={{
                padding: '20px 24px',
                borderBottom: '1px solid var(--border-paper)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                background: 'var(--surface-paper)'
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
                  Clinical Admission Form :: Ingest Drawer
                </span>
                <h3
                  className="font-serif"
                  style={{
                    fontSize: '22px',
                    fontWeight: 400,
                    color: 'var(--ink-primary)',
                    marginTop: '2px'
                  }}
                >
                  Admit Incident Stack Trace
                </h3>
              </div>

              <button
                type="button"
                onClick={onClose}
                style={{
                  background: 'none',
                  border: 'none',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '18px',
                  color: 'var(--ink-secondary)',
                  cursor: 'pointer',
                  padding: '4px 8px'
                }}
                aria-label="Close ingest drawer"
              >
                ✕
              </button>
            </div>

            {/* Presets Strip */}
            <div
              style={{
                padding: '12px 24px',
                borderBottom: '1px solid var(--border-paper-light)',
                background: 'var(--surface-paper-lifted)',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px'
              }}
            >
              <span className="font-mono" style={{ fontSize: '10px', color: 'var(--ink-tertiary)', textTransform: 'uppercase' }}>
                Load realistic trace scenario:
              </span>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {PRESETS.map((preset, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => {
                      setTraceText(preset.trace);
                      setErrorMsg(null);
                    }}
                    style={{
                      padding: '4px 10px',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '11px',
                      background: traceText === preset.trace ? 'var(--ink-primary)' : 'var(--surface-paper)',
                      color: traceText === preset.trace ? 'var(--surface-paper-card)' : 'var(--ink-primary)',
                      border: '1px solid var(--border-paper)',
                      borderRadius: '2px',
                      cursor: 'pointer'
                    }}
                  >
                    {preset.title}
                  </button>
                ))}
              </div>
            </div>

            {/* Main Form */}
            <form
              onSubmit={handleExecuteIngest}
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '24px',
                display: 'flex',
                flexDirection: 'column',
                gap: '16px'
              }}
            >
              {/* Error banner */}
              {errorMsg && (
                <div
                  style={{
                    padding: '8px 12px',
                    borderRadius: '2px',
                    background: 'var(--alarm-red-soft)',
                    border: '1px solid var(--alarm-red-border)',
                    color: 'var(--alarm-red)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px'
                  }}
                  role="alert"
                >
                  {errorMsg}
                </div>
              )}

              {/* Success message */}
              {successMsg && (
                <div
                  style={{
                    padding: '8px 12px',
                    borderRadius: '2px',
                    background: 'rgba(43, 229, 154, 0.15)',
                    border: '1px solid rgba(43, 229, 154, 0.4)',
                    color: '#0F6B40',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    fontWeight: 600
                  }}
                >
                  {successMsg}
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label className="font-mono" style={{ fontSize: '11px', color: 'var(--ink-secondary)', fontWeight: 600 }}>
                  Raw Stack Trace or Alert Payload:
                </label>
                <textarea
                  value={traceText}
                  onChange={(e) => {
                    setTraceText(e.target.value);
                    setErrorMsg(null);
                  }}
                  rows={8}
                  style={{
                    width: '100%',
                    padding: '12px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    lineHeight: '1.5',
                    background: 'var(--surface-paper-lifted)',
                    color: 'var(--ink-primary)',
                    border: '1px solid var(--border-paper)',
                    borderRadius: '2px',
                    outline: 'none',
                    resize: 'vertical'
                  }}
                  required
                />
              </div>

              {/* Sentinel Real-Time Parser Inspection */}
              <div
                style={{
                  background: 'var(--surface-paper)',
                  border: '1px solid var(--border-paper)',
                  borderRadius: '2px',
                  padding: '14px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px'
                }}
              >
                <span
                  className="font-mono"
                  style={{
                    fontSize: '11px',
                    color: 'var(--ink-primary)',
                    fontWeight: 600,
                    textTransform: 'uppercase'
                  }}
                >
                  Sentinel Autonomous Diagnostics Preview
                </span>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <span className="font-mono" style={{ fontSize: '10px', color: 'var(--ink-tertiary)' }}>
                    Culprit Frame Extracted:
                  </span>
                  <span className="font-mono" style={{ fontSize: '12px', color: 'var(--alarm-red)', fontWeight: 600 }}>
                    {parsedFile}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <span className="font-mono" style={{ fontSize: '10px', color: 'var(--ink-tertiary)' }}>
                    Recalled Precedent from Memory:
                  </span>
                  <span className="font-mono" style={{ fontSize: '11px', color: 'var(--memory-violet)' }}>
                    {matchedPrecedent}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <span className="font-mono" style={{ fontSize: '10px', color: 'var(--ink-tertiary)' }}>
                    Synthesized Diff Action:
                  </span>
                  <span className="font-sans" style={{ fontSize: '12px', color: 'var(--ink-secondary)' }}>
                    Propose length-prefixed patch, compute specHash, and issue 5-minute HMAC challenge appr_xxx.
                  </span>
                </div>
              </div>

              {/* Submit Button */}
              <div style={{ marginTop: 'auto', paddingTop: '12px' }}>
                <button
                  type="button"
                  onClick={handleExecuteIngest}
                  disabled={isIngesting}
                  style={{
                    width: '100%',
                    padding: '12px',
                    background: 'var(--ink-primary)',
                    color: 'var(--surface-paper-card)',
                    border: 'none',
                    borderRadius: '2px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '13px',
                    fontWeight: 600,
                    cursor: isIngesting ? 'wait' : 'pointer'
                  }}
                >
                  {isIngesting ? 'Sentinel Parsing & Admitting...' : 'Admit Patient Bed to Ward Board'}
                </button>
              </div>
            </form>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};
