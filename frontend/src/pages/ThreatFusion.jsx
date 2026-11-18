import { useState } from 'react';
import { Zap, AlertTriangle, CheckCircle, ChevronDown, ChevronUp } from 'lucide-react';
import FusionDiagram from '../components/FusionDiagram';
import RiskGauge from '../components/RiskGauge';
import { fuseThreat } from '../lib/api';
import { RISK_COLORS, riskToStatus } from '../lib/riskUtils';
import styles from './ThreatFusion.module.css';

const DEFAULTS = {
  email_content: '',
  url: '',
  login_features: null,
  network_features: null,
};

const SAMPLE_LOGIN = {
  hour_of_day: 3, day_of_week: 6, login_duration: 2, failed_attempts: 8,
  typing_speed: 2.5, mouse_movement: 20, ip_reputation_score: 0.95,
  is_new_device: 1, is_vpn: 1, country_risk_score: 0.85,
};

const SAMPLE_NETWORK = {
  duration: 0, protocol_type: 'tcp', service: 'http', flag: 'S0',
  src_bytes: 1032, dst_bytes: 0, land: 0, wrong_fragment: 0, urgent: 0,
  hot: 0, num_failed_logins: 0, logged_in: 0, num_compromised: 0,
  root_shell: 0, su_attempted: 0, num_root: 0, num_file_creations: 0,
  num_shells: 0, num_access_files: 0, num_outbound_cmds: 0,
  is_host_login: 0, is_guest_login: 0, count: 511, srv_count: 511,
  serror_rate: 1.0, srv_serror_rate: 1.0, rerror_rate: 0.0, srv_rerror_rate: 0.0,
  same_srv_rate: 1.0, diff_srv_rate: 0.0, srv_diff_host_rate: 0.0,
  dst_host_count: 255, dst_host_srv_count: 11, dst_host_same_srv_rate: 0.04,
  dst_host_diff_srv_rate: 0.06, dst_host_same_src_port_rate: 0.0,
  dst_host_srv_diff_host_rate: 0.0, dst_host_serror_rate: 1.0,
  dst_host_srv_serror_rate: 1.0, dst_host_rerror_rate: 0.0, dst_host_srv_rerror_rate: 0.0,
};

export default function ThreatFusion() {
  const [form, setForm] = useState({ ...DEFAULTS });
  const [includeLogin, setIncludeLogin] = useState(false);
  const [includeNetwork, setIncludeNetwork] = useState(false);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState({});

  function toggleExpand(key) {
    setExpanded(e => ({ ...e, [key]: !e[key] }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    const payload = {};
    if (form.email_content.trim()) payload.email_content = form.email_content.trim();
    if (form.url.trim()) payload.url = form.url.trim();
    if (includeLogin) payload.login_features = SAMPLE_LOGIN;
    if (includeNetwork) payload.network_features = SAMPLE_NETWORK;

    if (!Object.keys(payload).length) {
      setError('Please provide at least one input.');
      return;
    }

    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const data = await fuseThreat(payload);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function loadAllSamples() {
    setForm({
      email_content: `Dear Customer, your account has been suspended. Click to restore: http://secure-login.tk/restore`,
      url: 'http://paypal-secure-login.tk/account?verify=true',
    });
    setIncludeLogin(true);
    setIncludeNetwork(true);
  }

  return (
    <div className={styles.root}>
      <div className="page-header">
        <div>
          <div className="page-eyebrow">Analysis · Multi-Source</div>
          <h1 className="page-title">Threat Fusion Engine</h1>
          <p className="page-desc">
            Submit any combination of email, URL, login, and network inputs.
            The fusion engine aggregates all model outputs into a single composite risk verdict.
          </p>
        </div>
        <div className={styles.modelTag}><Zap size={13} /> Multi-Model Fusion</div>
      </div>

      <div className={styles.topGrid}>
        <div className={styles.diagramWrap}>
          <FusionDiagram width={440} height={240} active={loading || !!result} />
        </div>
        {result && (
          <div className={styles.verdictWrap}>
            <RiskGauge score={result.composite_risk_score} level={result.risk_level} />
            <div className={styles.verdictBadge} data-threat={result.is_threat}>
              {result.is_threat
                ? <><AlertTriangle size={16} /> THREAT DETECTED</>
                : <><CheckCircle size={16} /> NO ACTIVE THREAT</>
              }
            </div>
            <p className={styles.verdictSummary}>{result.summary}</p>
          </div>
        )}
      </div>

      <div className={styles.layout}>
        <div className={styles.formCol}>
          <div className={styles.formCard}>
            <form onSubmit={handleSubmit}>
              <div className="form-group" style={{ marginBottom: '1rem' }}>
                <label className="form-label">Email Content (optional)</label>
                <textarea
                  className="form-input"
                  rows={5}
                  placeholder="Paste email body…"
                  value={form.email_content}
                  onChange={e => setForm(f => ({ ...f, email_content: e.target.value }))}
                />
              </div>

              <div className="form-group" style={{ marginBottom: '1.5rem' }}>
                <label className="form-label">URL (optional)</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="https://example.com"
                  value={form.url}
                  onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
                />
              </div>

              <div className={styles.toggleRow}>
                <label className={styles.toggle}>
                  <input
                    type="checkbox"
                    checked={includeLogin}
                    onChange={e => setIncludeLogin(e.target.checked)}
                  />
                  <span className={styles.toggleSlider} />
                  Include login anomaly check (sample data)
                </label>
                <label className={styles.toggle}>
                  <input
                    type="checkbox"
                    checked={includeNetwork}
                    onChange={e => setIncludeNetwork(e.target.checked)}
                  />
                  <span className={styles.toggleSlider} />
                  Include network traffic check (sample data)
                </label>
              </div>

              {error && (
                <div className="alert alert-danger" style={{ margin: '1rem 0 0' }}>
                  <AlertTriangle size={15} /> {error}
                </div>
              )}

              <div className={styles.formFooter}>
                <button type="button" className="btn btn-outline" onClick={loadAllSamples} style={{ fontSize: '0.82rem' }}>
                  Load all sample data
                </button>
                <button type="submit" className="btn btn-primary" disabled={loading}>
                  {loading ? 'Fusing…' : <><Zap size={15} /> Run Fusion Analysis</>}
                </button>
              </div>
            </form>
          </div>
        </div>

        {result && (
          <div className={styles.resultCol}>
            {/* Individual model results */}
            {result.predictions && Object.entries(result.predictions).map(([key, pred]) => (
              <div key={key} className={styles.predCard}>
                <button className={styles.predHeader} onClick={() => toggleExpand(key)}>
                  <div className={styles.predLeft}>
                    <span className={`badge badge-${riskToStatus(pred.risk_level)}`}>{pred.risk_level}</span>
                    <span className={styles.predName}>{key.replace(/_/g, ' ').toUpperCase()}</span>
                  </div>
                  <div className={styles.predRight}>
                    <span className={styles.predScore}>{pred.risk_score?.toFixed(1) ?? '—'}</span>
                    {expanded[key] ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </div>
                </button>
                {expanded[key] && (
                  <div className={styles.predBody}>
                    <p className={styles.predDetail}><strong>Verdict:</strong> {pred.is_threat ? '⚠ Threat' : '✓ Clean'}</p>
                    <p className={styles.predDetail}><strong>Algorithm:</strong> {pred.algorithm}</p>
                    {pred.explanation?.summary && (
                      <p className={styles.predDetail}><strong>Reasoning:</strong> {pred.explanation.summary}</p>
                    )}
                  </div>
                )}
              </div>
            ))}

            {/* Recommendations */}
            {result.recommendations?.length > 0 && (
              <div className={styles.recommendCard}>
                <h3 className={styles.recommendTitle}>Recommendations</h3>
                <ul className={styles.recommendList}>
                  {result.recommendations.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Active threats */}
            {result.active_threats?.length > 0 && (
              <div className={styles.activeThreats}>
                <h3>Active Threats</h3>
                <div className={styles.threatTags}>
                  {result.active_threats.map(t => (
                    <span key={t} className="badge badge-danger">{t}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
