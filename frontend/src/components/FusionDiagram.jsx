import { useEffect, useRef } from 'react';

// Animated canvas diagram: 4 source nodes converge into central fusion node.
const SOURCES = [
  { label: 'Phishing', color: '#B86F52', icon: '✉' },
  { label: 'URL', color: '#8B5A42', icon: '🔗' },
  { label: 'Login', color: '#6B4226', icon: '👤' },
  { label: 'Network', color: '#4A2C1A', icon: '⚡' },
];

export default function FusionDiagram({ width = 480, height = 260, active = false }) {
  const ref = useRef(null);
  const animRef = useRef(null);
  const tRef = useRef(0);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    const cx = width * 0.72;
    const cy = height / 2;
    const r = 32;

    // Source positions (left side, evenly spaced)
    const sourcePositions = SOURCES.map((_, i) => ({
      x: width * 0.18,
      y: (height / (SOURCES.length + 1)) * (i + 1),
    }));

    // Pulses along each wire
    const pulses = SOURCES.map((_, i) => ({
      t: i * 0.25,
      speed: 0.008 + i * 0.001,
    }));

    function draw() {
      ctx.clearRect(0, 0, width, height);
      const t = tRef.current;

      // Draw connection lines
      sourcePositions.forEach((sp, i) => {
        const src = SOURCES[i];
        ctx.beginPath();
        ctx.moveTo(sp.x + 24, sp.y);
        ctx.bezierCurveTo(
          sp.x + (cx - sp.x) * 0.4, sp.y,
          cx - (cx - sp.x) * 0.4, cy,
          cx - r - 4, cy
        );
        ctx.strokeStyle = `rgba(184,111,82,0.2)`;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Animated pulse
        const pct = pulses[i].t;
        const bx = (p) => {
          const mx = sp.x + 24;
          return (
            (1 - p) ** 3 * mx +
            3 * (1 - p) ** 2 * p * (mx + (cx - mx) * 0.4) +
            3 * (1 - p) * p ** 2 * (cx - (cx - mx) * 0.4) +
            p ** 3 * (cx - r - 4)
          );
        };
        const by = (p) => {
          return (
            (1 - p) ** 3 * sp.y +
            3 * (1 - p) ** 2 * p * sp.y +
            3 * (1 - p) * p ** 2 * cy +
            p ** 3 * cy
          );
        };
        const px = bx(pct);
        const py = by(pct);

        ctx.beginPath();
        ctx.arc(px, py, 4, 0, Math.PI * 2);
        ctx.fillStyle = src.color;
        ctx.fill();
        ctx.beginPath();
        ctx.arc(px, py, 7, 0, Math.PI * 2);
        ctx.fillStyle = `${src.color}44`;
        ctx.fill();

        pulses[i].t = (pulses[i].t + pulses[i].speed) % 1;
      });

      // Source nodes
      sourcePositions.forEach((sp, i) => {
        const src = SOURCES[i];
        ctx.beginPath();
        ctx.arc(sp.x, sp.y, 20, 0, Math.PI * 2);
        ctx.fillStyle = `${src.color}18`;
        ctx.fill();
        ctx.beginPath();
        ctx.arc(sp.x, sp.y, 20, 0, Math.PI * 2);
        ctx.strokeStyle = src.color;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = src.color;
        ctx.fillText(src.icon, sp.x, sp.y);

        ctx.font = '500 10px Manrope, sans-serif';
        ctx.fillStyle = src.color;
        ctx.fillText(src.label, sp.x, sp.y + 30);
      });

      // Central fusion node (pulsing ring)
      const pulse = 1 + 0.08 * Math.sin(t * 0.05);
      ctx.beginPath();
      ctx.arc(cx, cy, r * pulse + 8, 0, Math.PI * 2);
      ctx.strokeStyle = active ? 'rgba(184,111,82,0.3)' : 'rgba(184,111,82,0.15)';
      ctx.lineWidth = 1;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      const grad = ctx.createRadialGradient(cx - 8, cy - 8, 2, cx, cy, r);
      grad.addColorStop(0, '#C9875F');
      grad.addColorStop(1, '#7A3D20');
      ctx.fillStyle = grad;
      ctx.fill();

      ctx.font = `bold 11px Manrope, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#fff';
      ctx.fillText('FUSION', cx, cy - 6);
      ctx.fillText('ENGINE', cx, cy + 7);

      tRef.current += 1;
      animRef.current = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, [width, height, active]);

  return (
    <canvas
      ref={ref}
      style={{ width, height, display: 'block' }}
    />
  );
}
