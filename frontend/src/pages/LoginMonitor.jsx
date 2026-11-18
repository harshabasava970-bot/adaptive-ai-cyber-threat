import { useState } from 'react';
import { User, AlertTriangle } from 'lucide-react';
import ResultCard from '../components/ResultCard';
import { detectLogin } from '../lib/api';
import styles from './DetectionPage.module.css';

const DEFAULTS = {
  hour_of_day: 3,
  day_of_week: 6,
  login_duration: 2,
  failed_attempts: 8,
  typing_speed: 2.5,
  mouse_movement: 20,
  ip_reputation_score: 0.95,
  is_new_device: 1,
  is_vpn: 1,
  country_risk_score: 0.85,
};

const FIELDS = [
  { key: 'hour_of_day', label: 'Hour of Day (0–23)', min: 0, max: 23, step: 1 },
  { key: 'day_of_week', label: 'Day of Week (0=Mon)', min: 0, max: 6, step: 1 },
  { key: 'login_duration', label: 'Session Duration (sec)', min: 0, max: 3600, step: 1 },
  { key: 'failed_attempts', label: 'Failed Attempts', min: 0, max: 50, step: 1 },
  { key: 'typing_speed', label: 'Typing Speed (chars/sec)', min: 0, max: 20, step: 0.1 },
  { key: 'mouse_movement', label: 'Mouse Movement (px)', min: 0, max: 5000, step: 1 },
  { key: 'ip_reputation_score', label: 'IP Reputation (0–1)', min: 0, max: 1, step: 0.01 },
  { key: 'is_new_device', label: 'New Device (0/1)', min: 0, max: 1, step: 1 },
  { key: 'is_vpn', label: 'VPN Detected (0/1)', min: 0, max: 1, step: 1 },
  { key: 'country_risk_score', label: 'Country Risk (0–1)', min: 0, max: 1, step: 0.01 },
];

export default function LoginMonitor() {
  const [form, setForm] = useState({ ...DEFAULTS });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  function update(key, val) {
    setForm(f => ({ ...f, [key]: parseFloat(val) }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const data = await detectLogin(form);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className={styles.root}>
      <div className="page-header">
        <div>
          <div className="page-eyebrow">Detection · Login</div>
          <h1 className="page-title">Anomalous Login Monitor</h1>
          <p className="page-desc">
            Enter login-session behavioural features. Isolation Forest and XGBoost ensemble
            detects credential-stuffing, impossible travel, and bot-driven login patterns.
          </p>
        </div>
        <div className={styles.modelTag}>XGBoost + Isolation Forest</div>
      </div>

      <div className={styles.layout}>
        <div className={styles.formCol}>
          <div className={styles.formCard}>
            <form onSubmit={handleSubmit}>
              <div className={styles.formGrid}>
                {FIELDS.map(f => (
                  <div key={f.key} className="form-group">
                    <label className="form-label">{f.label}</label>
                    <input
                      type="number"
                      className="form-input"
                      min={f.min}
                      max={f.max}
                      step={f.step}
                      value={form[f.key]}
                      onChange={e => update(f.key, e.target.value)}
                    />
                  </div>
                ))}
              </div>
              <div className={styles.formFooter}>
                <button
                  type="button"
                  className="btn btn-outline"
                  onClick={() => setForm({ ...DEFAULTS })}
                  style={{ fontSize: '0.82rem' }}
                >
                  Load anomalous sample
                </button>
                <button type="submit" className="btn btn-primary" disabled={loading}>
                  {loading ? 'Analysing…' : 'Analyse Login'}
                </button>
              </div>
            </form>

            {error && (
              <div className="alert alert-danger" style={{ marginTop: '1rem' }}>
                <AlertTriangle size={15} /> {error}
              </div>
            )}
          </div>

          <div className={styles.infoCard}>
            <h3 className={styles.infoTitle}>Detection signals</h3>
            <ul className={styles.infoList}>
              <li>Unusual login time (3 AM) combined with high failed attempts.</li>
              <li>New device + VPN + high-risk country triggers anomaly score.</li>
              <li>Isolation Forest provides unsupervised outlier score.</li>
              <li>XGBoost provides supervised binary classification.</li>
            </ul>
          </div>
        </div>

        <div className={styles.resultCol}>
          {result ? (
            <ResultCard result={result} />
          ) : (
            <div className={styles.emptyResult}>
              <img
                src="https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=600&q=80"
                alt="Cybersecurity access control"
                className={styles.emptyImg}
                loading="lazy"
              />
              <p className={styles.emptyText}>Analysis results will appear here</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
