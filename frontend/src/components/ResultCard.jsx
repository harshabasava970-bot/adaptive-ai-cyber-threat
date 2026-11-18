import { RISK_COLORS, RISK_BG, riskToStatus, scoreToPercent } from '../lib/riskUtils'
import styles from './ResultCard.module.css'

export default function ResultCard({ result, type }) {
  if (!result) return null
  const { risk_level, probability, is_threat, model_name, inference_time_ms, explanation } = result
  const pct    = scoreToPercent(probability)
  const color  = RISK_COLORS[risk_level] || RISK_COLORS.info
  const bg     = RISK_BG[risk_level]     || RISK_BG.info
  const status = riskToStatus(risk_level)

  const signals = explanation?.top_features?.slice(0, 5) || []
  const reasoning = explanation?.reasoning || ''

  return (
    <div className={styles.card} style={{ borderColor: color }}>
      {/* Header */}
      <div className={styles.header} style={{ background: bg }}>
        <div className={styles.verdict} style={{ color }}>
          {is_threat ? '⚠ Threat Detected' : '✓ Appears Safe'}
        </div>
        <div className={styles.badges}>
          <span className={`badge badge-${riskToStatus(risk_level)}`}>{risk_level?.toUpperCase()}</span>
          <span className={styles.statusBadge} style={{ color, background: bg, borderColor: color }}>
            {status}
          </span>
        </div>
      </div>

      {/* Stats row */}
      <div className={styles.stats}>
        <div className={styles.stat}>
          <div className={styles.statLabel}>Risk Score</div>
          <div className={styles.statVal} style={{ color }}>{pct}/100</div>
        </div>
        <div className={styles.stat}>
          <div className={styles.statLabel}>Probability</div>
          <div className={styles.statVal}>{(probability * 100).toFixed(1)}%</div>
        </div>
        <div className={styles.stat}>
          <div className={styles.statLabel}>Model</div>
          <div className={styles.statVal} style={{ fontSize: '0.78rem' }}>{model_name}</div>
        </div>
        <div className={styles.stat}>
          <div className={styles.statLabel}>Latency</div>
          <div className={styles.statVal}>{inference_time_ms?.toFixed(0)}ms</div>
        </div>
      </div>

      {/* Score bar */}
      <div className={styles.barWrap}>
        <div className={styles.bar}>
          <div className={styles.barFill} style={{ width: `${pct}%`, background: color }} />
        </div>
        <span className={styles.barLabel} style={{ color }}>{pct}%</span>
      </div>

      {/* Reasoning */}
      {reasoning && (
        <div className={styles.reasoning}>
          <h4>AI Reasoning</h4>
          <p>{reasoning}</p>
        </div>
      )}

      {/* Top signals */}
      {signals.length > 0 && (
        <div className={styles.signals}>
          <h4>Contributing Signals</h4>
          {signals.map((s, i) => (
            <div key={i} className={styles.signal}>
              <div className={styles.signalHeader}>
                <span className={styles.signalName}>{s.feature}</span>
                <span className={styles.signalScore} style={{ color }}>
                  {(s.importance * 100).toFixed(1)}
                </span>
              </div>
              <div className={styles.signalBar}>
                <div style={{ width: `${s.importance * 100}%`, background: color }} />
              </div>
              {s.detail && <p className={styles.signalDetail}>{s.detail}</p>}
            </div>
          ))}
        </div>
      )}

      {/* Recommendations */}
      {explanation?.recommendations?.length > 0 && (
        <div className={styles.recs}>
          <h4>Recommendations</h4>
          {explanation.recommendations.map((r, i) => (
            <div key={i} className={styles.rec}>
              <span style={{ color: r.includes('IMMEDIATE') ? RISK_COLORS.critical : RISK_COLORS.medium }}>→</span>
              <span>{r}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
