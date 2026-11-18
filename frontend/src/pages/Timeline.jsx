import { useEffect, useState } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { getRecentDetections } from '../lib/api';
import { riskToStatus, formatDate } from '../lib/riskUtils';
import styles from './Timeline.module.css';

export default function Timeline() {
  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [limit, setLimit] = useState(50);

  function load() {
    setLoading(true);
    setError(null);
    getRecentDetections(limit)
      .then(r => setDetections(r.detections || []))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }

  useEffect(() => { load(); }, [limit]);

  return (
    <div className={styles.root}>
      <div className="page-header">
        <div>
          <div className="page-eyebrow">Analysis · History</div>
          <h1 className="page-title">Detection Timeline</h1>
          <p className="page-desc">Chronological log of all threat-detection events.</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <select
            className="form-input"
            style={{ width: 'auto', fontSize: '0.85rem', padding: '0.4rem 0.8rem' }}
            value={limit}
            onChange={e => setLimit(Number(e.target.value))}
          >
            <option value={20}>Last 20</option>
            <option value={50}>Last 50</option>
          </select>
          <button className="btn btn-outline" onClick={load} style={{ fontSize: '0.82rem', padding: '0.5rem 1rem' }}>
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="alert alert-warning" style={{ marginBottom: '1.5rem' }}>
          <AlertTriangle size={15} /> {error}
        </div>
      )}

      {loading ? (
        <div className={styles.loading}>Loading detections…</div>
      ) : detections.length === 0 ? (
        <div className={styles.empty}>
          <img
            src="https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=600&q=80"
            alt="Empty analytics"
            style={{ width: 240, borderRadius: 16, opacity: 0.6 }}
            loading="lazy"
          />
          <p>No detections recorded yet. Run an analysis to see results here.</p>
        </div>
      ) : (
        <div className={styles.tableCard}>
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Threat Type</th>
                  <th>Model</th>
                  <th>Algorithm</th>
                  <th>Risk Level</th>
                  <th>Score</th>
                  <th>Probability</th>
                  <th>Verdict</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {detections.map((d, i) => (
                  <tr key={i}>
                    <td className={styles.numCell}>{i + 1}</td>
                    <td><span className={styles.typeTag}>{d.threat_type || '—'}</span></td>
                    <td className={styles.modelCell}>{d.model_name || '—'}</td>
                    <td className={styles.algoCell}>{d.algorithm || '—'}</td>
                    <td>
                      <span className={`badge badge-${riskToStatus(d.risk_level)}`}>
                        {d.risk_level || '—'}
                      </span>
                    </td>
                    <td className={styles.numCell}>{d.risk_score != null ? d.risk_score.toFixed(1) : '—'}</td>
                    <td className={styles.numCell}>
                      {d.probability != null ? `${(d.probability * 100).toFixed(1)}%` : '—'}
                    </td>
                    <td className={d.is_threat ? styles.threatCell : styles.cleanCell}>
                      {d.is_threat ? '⚠ Threat' : '✓ Clean'}
                    </td>
                    <td className={styles.timeCell}>{d.timestamp ? formatDate(d.timestamp) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className={styles.tableFooter}>
            Showing {detections.length} detection{detections.length !== 1 ? 's' : ''}
          </div>
        </div>
      )}
    </div>
  );
}
