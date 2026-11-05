import React, { useEffect, useRef } from 'react';

interface WaveformCanvasProps {
  severity: 'critical' | 'high' | 'medium' | 'low';
  isExpired?: boolean;
  isResolved?: boolean;
  height?: number;
  showScanline?: boolean;
}

export const WaveformCanvas: React.FC<WaveformCanvasProps> = ({
  severity,
  isExpired = false,
  isResolved = false,
  height = 70,
  showScanline = true
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const animFrameRef = useRef<number | null>(null);
  const xOffsetRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Respect prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Handle high DPI
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const width = rect.width || 280;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    // ECG waveform generator function
    const getEcgSample = (t: number): number => {
      if (isExpired) {
        // Flatline with subtle sensor noise
        return (Math.random() - 0.5) * 1.5;
      }

      if (isResolved) {
        // Calm steady sinus rhythm (period ~ 120 units)
        const phase = (t % 130) / 130;
        if (phase < 0.15) return 0;
        if (phase >= 0.15 && phase < 0.22) {
          // P wave
          return Math.sin(((phase - 0.15) / 0.07) * Math.PI) * 4;
        }
        if (phase >= 0.22 && phase < 0.28) return 0;
        if (phase >= 0.28 && phase < 0.30) {
          // Q dip
          return -4;
        }
        if (phase >= 0.30 && phase < 0.34) {
          // R spike (peak)
          return 28;
        }
        if (phase >= 0.34 && phase < 0.37) {
          // S dip
          return -9;
        }
        if (phase >= 0.37 && phase < 0.45) return 0;
        if (phase >= 0.45 && phase < 0.60) {
          // T wave
          return Math.sin(((phase - 0.45) / 0.15) * Math.PI) * 7;
        }
        return 0;
      }

      if (severity === 'critical') {
        // Rapid, erratic tachycardia with arrhythmia
        const phase = (t % 65) / 65;
        const jitter = (Math.sin(t * 0.1) + Math.cos(t * 0.05)) * 3;
        if (phase < 0.2) return jitter;
        if (phase >= 0.2 && phase < 0.24) return -6 + jitter;
        if (phase >= 0.24 && phase < 0.28) return 32 + jitter; // High voltage R peak
        if (phase >= 0.28 && phase < 0.33) return -12 + jitter;
        if (phase >= 0.33 && phase < 0.5) {
          return Math.sin(((phase - 0.33) / 0.17) * Math.PI) * 12 + jitter;
        }
        return jitter;
      }

      // Amber / Medium / High: Elevated rhythm
      const phase = (t % 90) / 90;
      if (phase < 0.15) return 0;
      if (phase >= 0.15 && phase < 0.22) {
        return Math.sin(((phase - 0.15) / 0.07) * Math.PI) * 5;
      }
      if (phase >= 0.22 && phase < 0.27) return 0;
      if (phase >= 0.27 && phase < 0.29) return -5;
      if (phase >= 0.29 && phase < 0.33) return 26; // R peak
      if (phase >= 0.33 && phase < 0.36) return -8;
      if (phase >= 0.36 && phase < 0.45) return 0;
      if (phase >= 0.45 && phase < 0.60) {
        return Math.sin(((phase - 0.45) / 0.15) * Math.PI) * 8;
      }
      return 0;
    };

    const centerY = height / 2;
    let traceColor = '#2BE59A'; // Phosphor green default inside monitor
    if (isExpired) {
      traceColor = '#E5352B'; // Alarm red flatline
    } else if (severity === 'critical') {
      traceColor = '#FF5247'; // Erratic red-orange pulse
    } else if (severity === 'high') {
      traceColor = '#F2A100'; // Amber warning
    } else if (isResolved) {
      traceColor = '#52B889'; // Muted healthy green
    }

    const draw = () => {
      ctx.clearRect(0, 0, width, height);

      // 1. Draw subtle phosphor ECG grid inside the monitor
      ctx.strokeStyle = 'rgba(43, 229, 154, 0.07)';
      ctx.lineWidth = 1;
      const gridSize = 12;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // 2. Draw ECG baseline trace
      ctx.beginPath();
      ctx.strokeStyle = traceColor;
      ctx.lineWidth = isExpired ? 2 : 1.8;
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';

      const speed = isExpired ? 1.0 : severity === 'critical' ? 2.5 : 1.6;
      const headX = (xOffsetRef.current * speed) % width;

      // Draw continuous waveform across screen
      for (let x = 0; x < width; x++) {
        const timeVal = x + xOffsetRef.current * speed;
        const val = getEcgSample(timeVal);
        const y = centerY - val;

        if (x === 0) {
          ctx.moveTo(x, y);
        } else {
          ctx.lineTo(x, y);
        }
      }
      ctx.stroke();

      // 3. Draw scanning cursor & phosphor glow head
      if (showScanline && !prefersReducedMotion && !isExpired) {
        ctx.fillStyle = traceColor;
        const headY = centerY - getEcgSample(headX + xOffsetRef.current * speed);
        ctx.beginPath();
        ctx.arc(headX, headY, 2.5, 0, Math.PI * 2);
        ctx.fill();

        // Subtle forward glow
        const glowGrad = ctx.createLinearGradient(headX, 0, Math.min(width, headX + 30), 0);
        glowGrad.addColorStop(0, 'rgba(43, 229, 154, 0.15)');
        glowGrad.addColorStop(1, 'transparent');
        ctx.fillStyle = glowGrad;
        ctx.fillRect(headX, 0, 30, height);
      }

      if (!prefersReducedMotion) {
        xOffsetRef.current += 1;
        animFrameRef.current = requestAnimationFrame(draw);
      }
    };

    draw();

    return () => {
      if (animFrameRef.current) {
        cancelAnimationFrame(animFrameRef.current);
      }
    };
  }, [severity, isExpired, isResolved, height, showScanline]);

  return (
    <div
      style={{
        width: '100%',
        height: `${height}px`,
        position: 'relative',
        background: '#040806',
        borderRadius: '6px',
        overflow: 'hidden'
      }}
      aria-label={`Live ECG vitals trace: ${isExpired ? 'Flatline expired' : severity}`}
    >
      <canvas
        ref={canvasRef}
        style={{
          width: '100%',
          height: `${height}px`,
          display: 'block'
        }}
      />
    </div>
  );
};

