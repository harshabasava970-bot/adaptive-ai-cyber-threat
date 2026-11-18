import { Shield, Github, ExternalLink } from 'lucide-react';
import styles from './About.module.css';

const MODELS = [
  {
    name: 'DistilBERT',
    task: 'Phishing Email Detection',
    desc: 'Fine-tuned on a 11,928-email dataset. WordPiece tokenisation, 6-layer transformer, 66M parameters distilled from BERT-base. Achieves 99.3% accuracy on the held-out test set.',
    badges: ['Transformer', 'NLP', 'Binary Classification'],
    img: 'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?w=600&q=80',
  },
  {
    name: 'XGBoost (URL)',
    task: 'Malicious URL Detection',
    desc: 'Trained on 11,430 URLs with 30 hand-crafted lexical and structural features. Gradient-boosted tree ensemble with SHAP explainability.',
    badges: ['XGBoost', 'Feature Engineering', 'SHAP'],
    img: 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&q=80',
  },
  {
    name: 'XGBoost + Isolation Forest',
    task: 'Anomalous Login Detection',
    desc: 'Dual-model ensemble combining supervised XGBoost classification with unsupervised Isolation Forest anomaly scoring on 10 behavioural features.',
    badges: ['Ensemble', 'Anomaly Detection', 'Behavioural AI'],
    img: 'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=600&q=80',
  },
  {
    name: 'XGBoost (NSL-KDD)',
    task: 'Network Intrusion Detection',
    desc: 'Trained on 125,973 NSL-KDD flow records with 41 features and 5 attack categories (Normal, DoS, Probe, R2L, U2R). 97.8% weighted F1-score.',
    badges: ['XGBoost', 'NSL-KDD', 'Multi-class'],
    img: 'https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&q=80',
  },
];

const TECH = [
  { label: 'Frontend', items: ['React 18', 'Vite', 'React Router 6', 'Recharts', 'Framer Motion', 'CSS Modules'] },
  { label: 'Backend API', items: ['FastAPI', 'Python 3.11', 'Uvicorn', 'Pydantic v2'] },
  { label: 'ML Libraries', items: ['scikit-learn', 'XGBoost', 'HuggingFace Transformers', 'SHAP', 'LIME', 'joblib'] },
  { label: 'Infrastructure', items: ['Vercel (frontend)', 'Render (API)', 'GitHub Actions CI'] },
];

export default function About() {
  return (
    <div className={styles.root}>
      {/* Hero */}
      <div className={styles.hero}>
        <img
          src="https://images.unsplash.com/photo-1573164713988-8665fc963095?w=1200&q=80"
          alt="Security operations centre"
          className={styles.heroImg}
          loading="lazy"
        />
        <div className={styles.heroOverlay} />
        <div className={styles.heroContent}>
          <div className={styles.heroBadge}><Shield size={14} /> B.Tech Capstone Project</div>
          <h1 className={styles.heroTitle}>
            Adaptive Explainable Multi-Source<br />
            Cyber Threat Detection Framework
          </h1>
          <p className={styles.heroSub}>
            using DistilBERT, XGBoost, Isolation Forest and SHAP-LIME
          </p>
        </div>
      </div>

      {/* Overview */}
      <section className={styles.section}>
        <div className={styles.sectionLabel}>Overview</div>
        <div className={styles.overviewGrid}>
          <div>
            <h2 className={styles.h2}>What this framework does</h2>
            <p className={styles.body}>
              This project unifies four independent machine-learning threat-detection
              systems under a single API and UI. Each model is independently trained and
              evaluated; a fusion engine then combines their outputs to produce a composite
              risk score for multi-vector attack scenarios.
            </p>
            <p className={styles.body} style={{ marginTop: '0.75rem' }}>
              Every prediction is accompanied by a human-readable explanation generated
              by SHAP (SHapley Additive exPlanations) or LIME (Local Interpretable
              Model-Agnostic Explanations), making the system transparent and auditable.
            </p>
            <div className={styles.linkRow}>
              <a
                href="https://github.com/harshabasava970-bot/adaptive-ai-cyber-threat"
                target="_blank"
                rel="noreferrer"
                className="btn btn-outline"
                style={{ fontSize: '0.85rem' }}
              >
                <Github size={15} /> GitHub Repository
              </a>
              <a
                href="https://cyber-threat-ai.streamlit.app"
                target="_blank"
                rel="noreferrer"
                className="btn btn-outline"
                style={{ fontSize: '0.85rem' }}
              >
                <ExternalLink size={15} /> Streamlit Version
              </a>
            </div>
          </div>
          <img
            src="https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=600&q=80"
            alt="Researcher reviewing model outputs"
            className={styles.overviewImg}
            loading="lazy"
          />
        </div>
      </section>

      {/* ML Models */}
      <section className={styles.section} style={{ background: 'rgba(184,111,82,0.04)', borderRadius: 24, padding: '3rem' }}>
        <div className={styles.sectionLabel}>Machine Learning</div>
        <h2 className={styles.h2}>Detection Models</h2>
        <div className={styles.modelGrid}>
          {MODELS.map(m => (
            <div key={m.name} className={styles.modelCard}>
              <div className={styles.modelImgWrap}>
                <img src={m.img} alt={m.task} className={styles.modelImg} loading="lazy" />
              </div>
              <div className={styles.modelBody}>
                <h3 className={styles.modelName}>{m.name}</h3>
                <span className={styles.modelTask}>{m.task}</span>
                <p className={styles.modelDesc}>{m.desc}</p>
                <div className={styles.badgeRow}>
                  {m.badges.map(b => (
                    <span key={b} className="badge badge-info">{b}</span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Tech stack */}
      <section className={styles.section}>
        <div className={styles.sectionLabel}>Architecture</div>
        <h2 className={styles.h2}>Technology Stack</h2>
        <div className={styles.techGrid}>
          {TECH.map(t => (
            <div key={t.label} className={styles.techCard}>
              <h3 className={styles.techLabel}>{t.label}</h3>
              <ul className={styles.techList}>
                {t.items.map(item => <li key={item}>{item}</li>)}
              </ul>
            </div>
          ))}
        </div>
      </section>

      {/* Architecture diagram (text) */}
      <section className={styles.section}>
        <div className={styles.sectionLabel}>System Design</div>
        <h2 className={styles.h2}>Data flow</h2>
        <div className={styles.flowCard}>
          <div className={styles.flowStep}>
            <div className={styles.flowIcon}>1</div>
            <div>
              <strong>Input ingestion</strong>
              <p>User submits email text, URL string, login metadata, or network flow features via REST API.</p>
            </div>
          </div>
          <div className={styles.flowArrow}>↓</div>
          <div className={styles.flowStep}>
            <div className={styles.flowIcon}>2</div>
            <div>
              <strong>Feature extraction</strong>
              <p>Each detector extracts domain-specific features: NLP tokenisation, URL structural parsing, numerical normalisation, or label encoding.</p>
            </div>
          </div>
          <div className={styles.flowArrow}>↓</div>
          <div className={styles.flowStep}>
            <div className={styles.flowIcon}>3</div>
            <div>
              <strong>Model inference</strong>
              <p>Pre-trained models (loaded from .joblib or HuggingFace safetensors) produce a probability score and binary classification.</p>
            </div>
          </div>
          <div className={styles.flowArrow}>↓</div>
          <div className={styles.flowStep}>
            <div className={styles.flowIcon}>4</div>
            <div>
              <strong>Explanation generation</strong>
              <p>SHAP TreeExplainer (XGBoost) or LIME TextExplainer (DistilBERT) generates feature-level importance scores.</p>
            </div>
          </div>
          <div className={styles.flowArrow}>↓</div>
          <div className={styles.flowStep}>
            <div className={styles.flowIcon}>5</div>
            <div>
              <strong>Fusion &amp; response</strong>
              <p>Optional: Fusion engine aggregates multi-source outputs. Structured JSON response returned to client.</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
