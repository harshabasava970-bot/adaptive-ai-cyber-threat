import { useState } from 'react';
import { Network as NetworkIcon, AlertTriangle } from 'lucide-react';
import ResultCard from '../components/ResultCard';
import { detectNetwork } from '../lib/api';
import styles from './DetectionPage.module.css';

const DEFAULTS = {
  duration: 0,
  protocol_type: 'tcp',
  service: 'http',
  flag: 'SF',
  src_bytes: 1032,
  dst_bytes: 0,
  land: 0,
  wrong_fragment: 0,
  urgent: 0,
  hot: 0,
  num_failed_logins: 0,
  logged_in: 0,
  num_compromised: 0,
  root_shell: 0,
  su_attempted: 0,
  num_root: 0,
  num_file_creations: 0,
  num_shells: 0,
  num_access_files: 0,
  num_outbound_cmds: 0,
  is_host_login: 0,
  is_guest_login: 0,
  count: 511,
  srv_count: 511,
  serror_rate: 1.0,
  srv_serror_rate: 1.0,
  rerror_rate: 0.0,
  srv_rerror_rate: 0.0,
  same_srv_rate: 1.0,
  diff_srv_rate: 0.0,
  srv_diff_host_rate: 0.0,
  dst_host_count: 255,
  dst_host_srv_count: 11,
  dst_host_same_srv_rate: 0.04,
  dst_host_diff_srv_rate: 0.06,
  dst_host_same_src_port_rate: 0.0,
  dst_host_srv_diff_host_rate: 0.0,
  dst_host_serror_rate: 1.0,
  dst_host_srv_serror_rate: 1.0,
  dst_host_rerror_rate: 0.0,
  dst_host_srv_rerror_rate: 0.0,
};

const NUMERIC_FIELDS = [
  'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
  'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
  'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
  'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
  'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
  'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
  'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
  'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
  'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
  'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
];

// Show a compact subset in the UI (the full payload uses DEFAULTS for the rest)
const PRIMARY_FIELDS = [
  { key: 'duration', label: 'Duration (sec)' },
  { key: 'src_bytes', label: 'Source Bytes' },
  { key: 'dst_bytes', label: 'Destination Bytes' },
  { key: 'count', label: 'Connection Count' },
  { key: 'serror_rate', label: 'SYN Error Rate' },
  { key: 'logged_in', label: 'Logged In (0/1)' },
  { key: 'num_failed_logins', label: 'Failed Logins' },
  { key: 'root_shell', label: 'Root Shell (0/1)' },
];

const PROTOCOL_OPTIONS = ['tcp', 'udp', 'icmp'];
const SERVICE_OPTIONS = ['http', 'ftp', 'smtp', 'ssh', 'dns', 'other'];
const FLAG_OPTIONS = ['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'S1', 'S2', 'S3', 'OTH'];

// Preset for DoS-like traffic
const DOS_SAMPLE = {
  ...DEFAULTS,
  duration: 0, src_bytes: 1032, dst_bytes: 0,
  count: 511, srv_count: 511, serror_rate: 1.0, srv_serror_rate: 1.0,
  logged_in: 0, flag: 'S0', protocol_type: 'tcp', service: 'http',
};

export default function Network() {
  const [form, setForm] = useState({ ...DEFAULTS });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  function update(key, val) {
    setForm(f => ({
      ...f,
      [key]: NUMERIC_FIELDS.includes(key) ? parseFloat(val) : val,
    }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const data = await detectNetwork(form);
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
          <div className="page-eyebrow">Detection · Network</div>
          <h1 className="page-title">Network Intrusion Detection</h1>
          <p className="page-desc">
            Enter NSL-KDD flow features. XGBoost trained on 125,000+ connections classifies
            network traffic as Normal, DoS, Probe, R2L, or U2R attack.
          </p>
        </div>
        <div className={styles.modelTag}>XGBoost · NSL-KDD · 41 Features</div>
      </div>

      <div className={styles.layout}>
        <div className={styles.formCol}>
          <div className={styles.formCard}>
            <form onSubmit={handleSubmit}>
              {/* Categorical selects */}
              <div className={styles.formGrid} style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
                <div className="form-group">
                  <label className="form-label">Protocol Type</label>
                  <select className="form-input" value={form.protocol_type} onChange={e => update('protocol_type', e.target.value)}>
                    {PROTOCOL_OPTIONS.map(o => <option key={o}>{o}</option>)}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Service</label>
                  <select className="form-input" value={form.service} onChange={e => update('service', e.target.value)}>
                    {SERVICE_OPTIONS.map(o => <option key={o}>{o}</option>)}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Flag</label>
                  <select className="form-input" value={form.flag} onChange={e => update('flag', e.target.value)}>
                    {FLAG_OPTIONS.map(o => <option key={o}>{o}</option>)}
                  </select>
                </div>
              </div>

              {/* Primary numeric fields */}
              <div className={styles.formGrid}>
                {PRIMARY_FIELDS.map(f => (
                  <div key={f.key} className="form-group">
                    <label className="form-label">{f.label}</label>
                    <input
                      type="number"
                      className="form-input"
                      step="any"
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
                  onClick={() => setForm({ ...DOS_SAMPLE })}
                  style={{ fontSize: '0.82rem' }}
                >
                  Load DoS attack sample
                </button>
                <button type="submit" className="btn btn-primary" disabled={loading}>
                  {loading ? 'Analysing…' : 'Analyse Traffic'}
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
            <h3 className={styles.infoTitle}>Attack taxonomy (NSL-KDD)</h3>
            <ul className={styles.infoList}>
              <li><strong>DoS</strong> — overwhelm resources (SYN flood, UDP flood).</li>
              <li><strong>Probe</strong> — reconnaissance scanning (portsweep, nmap).</li>
              <li><strong>R2L</strong> — remote-to-local unauthorised access.</li>
              <li><strong>U2R</strong> — user-to-root privilege escalation.</li>
            </ul>
          </div>
        </div>

        <div className={styles.resultCol}>
          {result ? (
            <ResultCard result={result} />
          ) : (
            <div className={styles.emptyResult}>
              <img
                src="https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&q=80"
                alt="Network traffic monitoring"
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
