import { useState } from 'react';
import { Link2, AlertTriangle } from 'lucide-react';
import ResultCard from '../components/ResultCard';
import { detectUrl } from '../lib/api';
import styles from './DetectionPage.module.css';

const SAMPLE = 'http://paypal-login-secure.tk/account/verify?token=abc123&redirect=http://evil.ru';

export default function UrlAnalyser() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const data = await detectUrl(url.trim());
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
          <div className="page-eyebrow">Detection · URL</div>
          <h1 className="page-title">Malicious URL Analyser</h1>
          <p className="page-desc">
            Enter any URL. XGBoost analyses structural features — domain age, path depth, special
            character density, TLD reputation — to detect phishing and malware distribution sites.
          </p>
        </div>
        <div className={styles.modelTag}>XGBoost · 30 URL Features</div>
      </div>

      <div className={styles.layout}>
        <div className={styles.formCol}>
          <div className={styles.formCard}>
            <form onSubmit={handleSubmit}>
              <label className="form-label">
                <Link2 size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                URL to Analyse
              </label>
              <input
                type="text"
                className="form-input"
                placeholder="https://example.com/path?param=value"
                value={url}
                onChange={e => setUrl(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
              <div className={styles.formFooter}>
                <button
                  type="button"
                  className="btn btn-outline"
                  onClick={() => setUrl(SAMPLE)}
                  style={{ fontSize: '0.82rem' }}
                >
                  Load sample malicious URL
                </button>
                <button type="submit" className="btn btn-primary" disabled={loading || !url.trim()}>
                  {loading ? 'Analysing…' : 'Analyse URL'}
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
            <h3 className={styles.infoTitle}>Feature extraction</h3>
            <ul className={styles.infoList}>
              <li>URL length, path depth, subdomain count, special character ratio.</li>
              <li>TLD risk score, hyphen/at-sign presence, IP-address usage.</li>
              <li>Redirect count, query parameter count, entropy of hostname.</li>
              <li>SHAP values identify which features drove the classification.</li>
            </ul>
          </div>
        </div>

        <div className={styles.resultCol}>
          {result ? (
            <ResultCard result={result} />
          ) : (
            <div className={styles.emptyResult}>
              <img
                src="https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&q=80"
                alt="Network security monitoring"
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
