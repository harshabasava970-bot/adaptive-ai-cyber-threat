import { useState } from 'react';
import { Mail, AlertTriangle } from 'lucide-react';
import ResultCard from '../components/ResultCard';
import { detectPhishing } from '../lib/api';
import styles from './DetectionPage.module.css';

const SAMPLE = `Dear Customer,

Your account has been suspended due to suspicious activity. 
Click here immediately to verify your identity and restore access:
http://secure-login-verify.tk/account/restore

Failure to verify within 24 hours will result in permanent account closure.

Security Team
customer-security@accounts-verify.tk`;

export default function Phishing() {
  const [text, setText] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!text.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const data = await detectPhishing(text.trim());
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
          <div className="page-eyebrow">Detection · Email</div>
          <h1 className="page-title">Phishing Email Detection</h1>
          <p className="page-desc">
            Paste the full email body. DistilBERT analyses linguistic patterns, urgency cues, and
            social-engineering signals to classify it as phishing or legitimate.
          </p>
        </div>
        <div className={styles.modelTag}>DistilBERT + TF-IDF/LogReg</div>
      </div>

      <div className={styles.layout}>
        <div className={styles.formCol}>
          <div className={styles.formCard}>
            <form onSubmit={handleSubmit}>
              <label className="form-label">
                <Mail size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                Email Content
              </label>
              <textarea
                className="form-input"
                rows={14}
                placeholder="Paste the email body here…"
                value={text}
                onChange={e => setText(e.target.value)}
                style={{ resize: 'vertical', fontFamily: 'var(--font-body)', fontSize: '0.9rem' }}
              />
              <div className={styles.formFooter}>
                <button
                  type="button"
                  className="btn btn-outline"
                  onClick={() => setText(SAMPLE)}
                  style={{ fontSize: '0.82rem' }}
                >
                  Load sample phishing email
                </button>
                <button type="submit" className="btn btn-primary" disabled={loading || !text.trim()}>
                  {loading ? 'Analysing…' : 'Analyse Email'}
                </button>
              </div>
            </form>

            {error && (
              <div className="alert alert-danger" style={{ marginTop: '1rem' }}>
                <AlertTriangle size={15} /> {error}
              </div>
            )}
          </div>

          {/* Context card */}
          <div className={styles.infoCard}>
            <h3 className={styles.infoTitle}>How it works</h3>
            <ul className={styles.infoList}>
              <li>Text is tokenised with DistilBERT's WordPiece tokeniser.</li>
              <li>A fine-tuned DistilBERT classifier produces a phishing probability.</li>
              <li>A TF-IDF + Logistic Regression ensemble provides a secondary signal.</li>
              <li>LIME identifies which words most influenced the classification.</li>
            </ul>
          </div>
        </div>

        <div className={styles.resultCol}>
          {result ? (
            <ResultCard result={result} />
          ) : (
            <div className={styles.emptyResult}>
              <img
                src="https://images.unsplash.com/photo-1563986768609-322da13575f3?w=600&q=80"
                alt="Cybersecurity email scanning"
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
