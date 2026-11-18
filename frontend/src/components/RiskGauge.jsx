import { RISK_COLORS } from '../lib/riskUtils';

const SIZE = 140;
const STROKE = 12;
const R = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = Math.PI * R; // half circle

export default function RiskGauge({ score = 0, level = 'Unknown' }) {
  const pct = Math.min(Math.max(score, 0), 100) / 100;
  const offset = CIRCUMFERENCE * (1 - pct);
  const color = RISK_COLORS[level] || '#94a3b8';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
      <svg width={SIZE} height={SIZE / 2 + STROKE} viewBox={`0 0 ${SIZE} ${SIZE / 2 + STROKE}`}>
        {/* Background arc */}
        <path
          d={`M ${STROKE / 2} ${SIZE / 2} A ${R} ${R} 0 0 1 ${SIZE - STROKE / 2} ${SIZE / 2}`}
          fill="none"
          stroke="var(--border)"
          strokeWidth={STROKE}
          strokeLinecap="round"
        />
        {/* Foreground arc */}
        <path
          d={`M ${STROKE / 2} ${SIZE / 2} A ${R} ${R} 0 0 1 ${SIZE - STROKE / 2} ${SIZE / 2}`}
          fill="none"
          stroke={color}
          strokeWidth={STROKE}
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4,0,0.2,1)' }}
        />
        {/* Score text */}
        <text
          x={SIZE / 2}
          y={SIZE / 2 - 4}
          textAnchor="middle"
          fontSize="22"
          fontWeight="700"
          fontFamily="var(--font-display)"
          fill="var(--espresso)"
        >
          {Math.round(score)}
        </text>
        <text
          x={SIZE / 2}
          y={SIZE / 2 + 14}
          textAnchor="middle"
          fontSize="10"
          fontWeight="500"
          fontFamily="var(--font-body)"
          fill={color}
          textTransform="uppercase"
        >
          {level}
        </text>
      </svg>
      <span style={{ fontSize: '0.72rem', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
        Risk Score
      </span>
    </div>
  );
}
