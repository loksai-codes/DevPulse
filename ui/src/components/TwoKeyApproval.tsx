import React, { useState, useEffect, useRef, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  Incident,
  ApprovalResult,
  ALLOWED_MAINTAINERS,
  AUTHORIZED_SWITCH_ORIGIN
} from '../adapters';

interface TwoKeyApprovalProps {
  incident: Incident;
  isReadComplete: boolean;
  onApprove: (incidentId: string) => Promise<ApprovalResult>;
  currentApprover: string;
  currentOrigin: string;
  onApproverChange: (approver: string) => void;
  onOriginChange: (origin: string) => void;
}

export const TwoKeyApproval: React.FC<TwoKeyApprovalProps> = ({
  incident,
  isReadComplete,
  onApprove,
  currentApprover,
  currentOrigin,
  onApproverChange,
  onOriginChange
}) => {
  const [holdProgress, setHoldProgress] = useState<number>(0); // 0 to 1
  const [isHolding, setIsHolding] = useState<boolean>(false);
  const [approvalResult, setApprovalResult] = useState<ApprovalResult | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [timeLeft, setTimeLeft] = useState<string>('05:00');
  const [isExpired, setIsExpired] = useState<boolean>(false);
  const [intruderAlarm, setIntruderAlarm] = useState<boolean>(false);

  const holdStartRef = useRef<number | null>(null);
  const animFrameRef = useRef<number | null>(null);
  const HOLD_DURATION_MS = 1200; // 1.2s requirement

  // 5:00 Challenge TTL timer calculation
  useEffect(() => {
    if (!incident.challenge || incident.challenge.status !== 'open') {
      if (incident.challenge?.status === 'expired') {
        setIsExpired(true);
        setTimeLeft('00:00');
      }
      return;
    }

    const checkTime = () => {
      const expiresAt = new Date(incident.challenge!.expiresAt).getTime();
      const diff = expiresAt - Date.now();
      if (diff <= 0) {
        setIsExpired(true);
        setTimeLeft('00:00');
      } else {
        const mins = Math.floor(diff / 60000);
        const secs = Math.floor((diff % 60000) / 1000);
        setTimeLeft(`${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`);
        setIsExpired(false);
      }
    };

    checkTime();
    const interval = setInterval(checkTime, 1000);
    return () => clearInterval(interval);
  }, [incident.challenge]);

  // Check origin intruder state
  useEffect(() => {
    const isBridged =
      currentOrigin.toLowerCase().includes('slack') ||
      currentOrigin.toLowerCase().includes('discord') ||
      currentOrigin.toLowerCase().includes('bridge');
    setIntruderAlarm(isBridged);
  }, [currentOrigin]);

  const isAllowlisted = ALLOWED_MAINTAINERS.includes(currentApprover);
  const isConsumed = incident.challenge?.status === 'consumed';
  const isLocked = !isAllowlisted || !isReadComplete || isExpired || isConsumed || isSubmitting;

  const triggerApproval = useCallback(async () => {
    setIsSubmitting(true);
    try {
      const result = await onApprove(incident.id);
      setApprovalResult(result);
    } finally {
      setIsSubmitting(false);
      setIsHolding(false);
      setHoldProgress(0);
    }
  }, [incident.id, onApprove]);

  // Press-and-hold animation loop
  const startHold = useCallback(() => {
    if (isLocked) return;
    setIsHolding(true);
    holdStartRef.current = performance.now();

    const loop = (now: number) => {
      if (!holdStartRef.current) return;
      const elapsed = now - holdStartRef.current;
      const progress = Math.min(1, elapsed / HOLD_DURATION_MS);
      setHoldProgress(progress);

      if (progress >= 1) {
        // Complete! Two-key turned
        holdStartRef.current = null;
        triggerApproval();
      } else {
        animFrameRef.current = requestAnimationFrame(loop);
      }
    };

    animFrameRef.current = requestAnimationFrame(loop);
  }, [isLocked, triggerApproval]);

  const cancelHold = useCallback(() => {
    if (animFrameRef.current) {
      cancelAnimationFrame(animFrameRef.current);
      animFrameRef.current = null;
    }
    holdStartRef.current = null;
    setIsHolding(false);
    setHoldProgress(0);
  }, []);

  // Keyboard accessibility: Hold Space or Enter
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if ((e.key === ' ' || e.key === 'Enter') && !isHolding && !isLocked) {
      e.preventDefault();
      startHold();
    }
  };

  const handleKeyUp = (e: React.KeyboardEvent) => {
    if (e.key === ' ' || e.key === 'Enter') {
      e.preventDefault();
      cancelHold();
    }
  };

  // Rejection quick tests
  const testUnauthorized = () => {
    onApproverChange('intern_guest_read_only');
    onOriginChange(AUTHORIZED_SWITCH_ORIGIN);
    setApprovalResult(null);
  };

  const testBridgedSlack = () => {
    onApproverChange(ALLOWED_MAINTAINERS[0]!);
    onOriginChange('slack_webhook_bridge');
    setApprovalResult(null);
  };

  const testValidMaintainer = () => {
    onApproverChange(ALLOWED_MAINTAINERS[0]!);
    onOriginChange(AUTHORIZED_SWITCH_ORIGIN);
    setApprovalResult(null);
  };

  return (
    <div
      className="paper-card"
      style={{
        padding: '16px',
        background: 'var(--surface-paper-card)',
        border: intruderAlarm ? '1.5px solid var(--alarm-red)' : '1px solid var(--border-paper)',
        display: 'flex',
        flexDirection: 'column',
        gap: '14px',
        position: 'relative'
      }}
      aria-live="polite"
    >
      {/* Intruder Alarm Strip for Bridged Origins */}
      {intruderAlarm && (
        <div
          style={{
            background: 'var(--alarm-red)',
            color: '#FFFFFF',
            padding: '6px 12px',
            borderRadius: '2px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            fontWeight: 600,
            animation: 'pulse 1.2s infinite'
          }}
        >
          <span>⚠ INTRUDER ALARM: BRIDGED ORIGIN DETECTED</span>
          <span>{currentOrigin.toUpperCase()}</span>
        </div>
      )}

      {/* Header & Challenge Timer Physical Gauge */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <span
            className="font-mono"
            style={{
              fontSize: '10px',
              color: 'var(--ink-secondary)',
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              fontWeight: 600
            }}
          >
            Human-In-The-Loop Governance
          </span>
          <h4
            className="font-serif"
            style={{
              fontSize: '18px',
              fontWeight: 400,
              color: 'var(--ink-primary)'
            }}
          >
            Two-Key Turn Authorization
          </h4>
        </div>

        {/* 5:00 Physical Countdown Gauge */}
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-end',
            fontFamily: 'var(--font-mono)'
          }}
        >
          <span
            style={{
              fontSize: '16px',
              fontWeight: 600,
              color: isExpired ? 'var(--alarm-red)' : 'var(--amber-pending)'
            }}
          >
            {timeLeft}
          </span>
          <span style={{ fontSize: '9px', color: 'var(--ink-tertiary)', textTransform: 'uppercase' }}>
            5:00 HMAC TTL
          </span>
        </div>
      </div>

      {/* Bound specHash & Challenge Token Details */}
      <div
        style={{
          background: 'var(--surface-paper)',
          border: '1px solid var(--border-paper-light)',
          padding: '8px 10px',
          borderRadius: '2px',
          fontSize: '11px',
          fontFamily: 'var(--font-mono)',
          display: 'flex',
          flexDirection: 'column',
          gap: '4px'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ color: 'var(--ink-secondary)' }}>Challenge ID:</span>
          <span style={{ fontWeight: 600, color: 'var(--ink-primary)' }}>
            {incident.challenge?.id || 'none'}
          </span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ color: 'var(--ink-secondary)' }}>Bound specHash:</span>
          <span style={{ color: 'var(--ink-primary)' }}>
            {incident.specHash.slice(0, 14)}...{incident.specHash.slice(-8)}
          </span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ color: 'var(--ink-secondary)' }}>Attending Maintainer:</span>
          <span
            style={{
              fontWeight: 600,
              color: isAllowlisted ? 'var(--ink-primary)' : 'var(--alarm-red)'
            }}
          >
            {currentApprover} {isAllowlisted ? '(Allowlisted)' : '(UNAUTHORIZED)'}
          </span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ color: 'var(--ink-secondary)' }}>Origin Channel:</span>
          <span style={{ color: intruderAlarm ? 'var(--alarm-red)' : 'var(--ink-primary)' }}>
            {currentOrigin}
          </span>
        </div>
      </div>

      {/* Physical Two-Key Turn Control (Press-and-Hold 1.2s) */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '8px',
          padding: '10px 0'
        }}
      >
        <div
          role="button"
          tabIndex={isLocked ? -1 : 0}
          onPointerDown={startHold}
          onPointerUp={cancelHold}
          onPointerLeave={cancelHold}
          onTouchStart={startHold}
          onTouchEnd={cancelHold}
          onKeyDown={handleKeyDown}
          onKeyUp={handleKeyUp}
          style={{
            width: '100px',
            height: '100px',
            borderRadius: '50%',
            position: 'relative',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: isLocked ? 'not-allowed' : 'pointer',
            userSelect: 'none',
            outline: 'none',
            background: isLocked
              ? '#D8DEC8'
              : 'radial-gradient(circle, #D4A017 0%, #B8860B 60%, #805E09 100%)',
            boxShadow: isHolding
              ? 'inset 0 4px 10px rgba(0,0,0,0.6), 0 0 12px rgba(184, 134, 11, 0.4)'
              : '0 4px 12px rgba(20, 32, 26, 0.25), inset 0 1px 1px rgba(255,255,255,0.4)',
            transition: 'transform 0.1s ease, box-shadow 0.1s ease',
            transform: isHolding ? 'scale(0.96)' : 'scale(1)'
          }}
          aria-label={
            isLocked
              ? `Key locked: ${
                  !isReadComplete
                    ? 'Prescription unread'
                    : !isAllowlisted
                    ? 'Not on maintainer allowlist'
                    : isExpired
                    ? 'Challenge expired'
                    : 'Awaiting execution'
                }`
              : 'Two-key authorization turn. Press and hold for 1.2 seconds.'
          }
        >
          {/* Radial SVG Progress Gauge Ring */}
          <svg
            width="114"
            height="114"
            style={{
              position: 'absolute',
              top: '-7px',
              left: '-7px',
              pointerEvents: 'none',
              transform: 'rotate(-90deg)'
            }}
          >
            <circle
              cx="57"
              cy="57"
              r="50"
              fill="none"
              stroke="rgba(20, 32, 26, 0.15)"
              strokeWidth="4"
            />
            <circle
              cx="57"
              cy="57"
              r="50"
              fill="none"
              stroke={intruderAlarm ? 'var(--alarm-red)' : '#2BE59A'}
              strokeWidth="5"
              strokeDasharray={2 * Math.PI * 50}
              strokeDashoffset={2 * Math.PI * 50 * (1 - holdProgress)}
              strokeLinecap="round"
              style={{
                transition: isHolding ? 'none' : 'stroke-dashoffset 0.18s ease-out'
              }}
            />
          </svg>

          {/* Mechanical Brass Key Barrel & Slot */}
          <div
            style={{
              width: '46px',
              height: '46px',
              borderRadius: '50%',
              background: isLocked ? '#9EAA96' : '#2A2006',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: 'inset 0 2px 5px rgba(0,0,0,0.8)'
            }}
          >
            {isLocked ? (
              /* Locked Padlock Icon */
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" strokeWidth="2.2">
                <rect x="3" y="11" width="18" height="11" rx="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            ) : (
              /* Brass Turning Key */
              <motion.div
                animate={{ rotate: holdProgress * 90 }}
                style={{
                  width: '28px',
                  height: '6px',
                  background: '#E8BF4D',
                  borderRadius: '2px',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.5)'
                }}
              />
            )}
          </div>
        </div>

        {/* Action Prompt or Interlock Explanation */}
        <div style={{ textAlign: 'center' }}>
          <span
            className="font-mono"
            style={{
              fontSize: '11px',
              fontWeight: 600,
              color: isLocked ? 'var(--alarm-red)' : 'var(--ink-primary)'
            }}
          >
            {!isReadComplete
              ? 'Interlock: Scroll diff 100% to unlock key'
              : !isAllowlisted
              ? 'Key Slot Locked: User not in maintainer allowlist'
              : intruderAlarm
              ? 'Interlock: Bridged origin forbidden'
              : isExpired
              ? 'Challenge Expired: 5-minute TTL elapsed'
              : isConsumed
              ? 'Challenge Consumed: Runner executing'
              : isHolding
              ? `Turning key... ${Math.round(holdProgress * 100)}%`
              : 'Hold Key 1.2s to Sign & Turn'}
          </span>
          <p
            className="font-sans"
            style={{ fontSize: '11px', color: 'var(--ink-secondary)', marginTop: '2px' }}
          >
            {!isLocked && 'Keyboard: Hold Space/Enter | Touch: Press and hold'}
          </p>
        </div>
      </div>

      {/* Security Rejection Diagnostic Display */}
      {approvalResult && !approvalResult.accepted && (
        <div
          style={{
            background: 'var(--alarm-red-soft)',
            border: '1px solid var(--alarm-red-border)',
            borderRadius: '2px',
            padding: '10px 12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '4px'
          }}
          role="alert"
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span
              className="font-mono"
              style={{
                fontSize: '11px',
                fontWeight: 600,
                color: 'var(--alarm-red)',
                textTransform: 'uppercase'
              }}
            >
              Rejection Code: {approvalResult.code}
            </span>
          </div>
          <span className="font-sans" style={{ fontSize: '12px', color: 'var(--ink-primary)' }}>
            {approvalResult.reason}
          </span>
        </div>
      )}

      {/* Interactive Security Rejection Testing Panel */}
      <div
        style={{
          borderTop: '1px solid var(--border-paper-light)',
          paddingTop: '10px',
          display: 'flex',
          flexDirection: 'column',
          gap: '6px'
        }}
      >
        <span
          className="font-mono"
          style={{
            fontSize: '10px',
            color: 'var(--ink-tertiary)',
            textTransform: 'uppercase',
            letterSpacing: '0.04em'
          }}
        >
          Interactive Security Scenarios:
        </span>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          <button
            onClick={testValidMaintainer}
            style={{
              padding: '3px 8px',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              border: isAllowlisted && !intruderAlarm ? '1px solid var(--ink-primary)' : '1px solid var(--border-paper)',
              background: isAllowlisted && !intruderAlarm ? 'var(--surface-paper-lifted)' : 'var(--surface-paper)',
              color: 'var(--ink-primary)',
              borderRadius: '2px',
              cursor: 'pointer'
            }}
          >
            Attending (Dr. Sarah Lin)
          </button>
          <button
            onClick={testUnauthorized}
            style={{
              padding: '3px 8px',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              border: !isAllowlisted ? '1px solid var(--alarm-red)' : '1px solid var(--border-paper)',
              background: 'var(--surface-paper)',
              color: !isAllowlisted ? 'var(--alarm-red)' : 'var(--ink-secondary)',
              borderRadius: '2px',
              cursor: 'pointer'
            }}
          >
            Test Non-Allowlist
          </button>
          <button
            onClick={testBridgedSlack}
            style={{
              padding: '3px 8px',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              border: intruderAlarm ? '1px solid var(--alarm-red)' : '1px solid var(--border-paper)',
              background: 'var(--surface-paper)',
              color: intruderAlarm ? 'var(--alarm-red)' : 'var(--ink-secondary)',
              borderRadius: '2px',
              cursor: 'pointer'
            }}
          >
            Test Bridged Slack
          </button>
        </div>
      </div>
    </div>
  );
};

