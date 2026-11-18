import { useEffect, useRef } from 'react';

// Pure canvas 2-D animated network globe — no Three.js dependency required at runtime.
// Draws a rotating sphere with latitude/longitude grid lines and animated node connections.

const NODES = 42;
const LINKS = 60;

function spherePoint(lat, lon, r) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  return {
    x: r * Math.sin(phi) * Math.cos(theta),
    y: r * Math.cos(phi),
    z: r * Math.sin(phi) * Math.sin(theta),
  };
}

function project(x, y, z, cx, cy, rot) {
  const cosR = Math.cos(rot);
  const sinR = Math.sin(rot);
  const rx = x * cosR - z * sinR;
  const rz = x * sinR + z * cosR;
  const scale = 400 / (400 + rz);
  return { px: cx + rx * scale, py: cy - y * scale, z: rz, scale };
}

export default function Globe({ size = 420 }) {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const rotRef = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    ctx.scale(dpr, dpr);

    const R = size * 0.38;
    const cx = size / 2;
    const cy = size / 2;

    // Generate fixed nodes on sphere surface
    const nodes = Array.from({ length: NODES }, () => {
      const lat = Math.random() * 160 - 80;
      const lon = Math.random() * 360 - 180;
      return { lat, lon, ...spherePoint(lat, lon, R) };
    });

    // Generate random links between nodes
    const links = Array.from({ length: LINKS }, () => ({
      a: Math.floor(Math.random() * NODES),
      b: Math.floor(Math.random() * NODES),
      progress: Math.random(),
      speed: 0.003 + Math.random() * 0.005,
      active: Math.random() > 0.4,
    }));

    function draw() {
      ctx.clearRect(0, 0, size, size);
      const rot = rotRef.current;

      // Sphere background gradient
      const grad = ctx.createRadialGradient(cx - R * 0.2, cy - R * 0.2, R * 0.1, cx, cy, R);
      grad.addColorStop(0, 'rgba(184,111,82,0.08)');
      grad.addColorStop(1, 'rgba(42,31,23,0.03)');
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.fill();

      // Grid lines (lat/lon)
      ctx.strokeStyle = 'rgba(184,111,82,0.12)';
      ctx.lineWidth = 0.5;
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        for (let lon = -180; lon <= 180; lon += 4) {
          const p = spherePoint(lat, lon, R);
          const { px, py, z } = project(p.x, p.y, p.z, cx, cy, rot);
          if (z < 0) { ctx.beginPath(); continue; }
          lon === -180 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
        }
        ctx.stroke();
      }
      for (let lon = -180; lon <= 180; lon += 30) {
        ctx.beginPath();
        for (let lat = -80; lat <= 80; lat += 4) {
          const p = spherePoint(lat, lon, R);
          const { px, py, z } = project(p.x, p.y, p.z, cx, cy, rot);
          if (z < 0) { ctx.beginPath(); continue; }
          lat === -80 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
        }
        ctx.stroke();
      }

      // Project all nodes
      const projected = nodes.map(n => ({
        ...project(n.x, n.y, n.z, cx, cy, rot),
        orig: n,
      }));

      // Draw links
      links.forEach(link => {
        if (!link.active) return;
        const a = projected[link.a];
        const b = projected[link.b];
        if (a.z < -R * 0.3 || b.z < -R * 0.3) return;
        const alpha = Math.min(a.scale, b.scale) * 0.6;
        ctx.beginPath();
        ctx.moveTo(a.px, a.py);
        ctx.lineTo(b.px, b.py);
        ctx.strokeStyle = `rgba(184,111,82,${alpha * 0.4})`;
        ctx.lineWidth = 0.8;
        ctx.stroke();

        // Animated pulse along link
        const t = link.progress;
        const px = a.px + (b.px - a.px) * t;
        const py = a.py + (b.py - a.py) * t;
        ctx.beginPath();
        ctx.arc(px, py, 2.5 * alpha, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(184,111,82,${alpha * 0.9})`;
        ctx.fill();

        link.progress = (link.progress + link.speed) % 1;
      });

      // Draw nodes
      projected.forEach(n => {
        if (n.z < -R * 0.1) return;
        const alpha = ((n.z + R) / (2 * R)) * 0.8 + 0.2;
        const r = 3 * n.scale * alpha;
        ctx.beginPath();
        ctx.arc(n.px, n.py, r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(184,111,82,${alpha})`;
        ctx.fill();
        // Glow ring on front nodes
        if (n.z > R * 0.5) {
          ctx.beginPath();
          ctx.arc(n.px, n.py, r + 3, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(184,111,82,0.25)`;
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      });

      rotRef.current += 0.003;
      animRef.current = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, [size]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        width: size,
        height: size,
        display: 'block',
        borderRadius: '50%',
        background: 'transparent',
      }}
    />
  );
}
