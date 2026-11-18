import { Link } from 'react-router-dom';
import { Shield, Mail, Link2, User, Network, Zap, ArrowRight, Github } from 'lucide-react';
import Globe from '../components/Globe';
import styles from './Landing.module.css';

const MODULES = [
  {
    icon: Mail,
    title: 'Phishing Email Detection',
    desc: 'DistilBERT transformer analyses email content to identify social-engineering patterns and malicious intent with high precision.',
    path: '/phishing',
    img: 'https://images.unsplash.com/photo-1563986768609-322da13575f3?w=600&q=80',
  },
  {
    icon: Link2,
    title: 'Malicious URL Analysis',
    desc: 'XGBoost model deconstructs URL structure, domain reputation, and lexical features to flag phishing and drive-by-download links.',
    path: '/url',
    img: 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&q=80',
  },
  {
    icon: User,
    title: 'Anomalous Login Monitor',
    desc: 'Isolation Forest and XGBoost ensemble detects credential-stuffing, impossible travel, and behavioural outliers in real time.',
    path: '/login',
    img: 'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=600&q=80',
  },
  {
    icon: Network,
    title: 'Network Intrusion Detection',
    desc: 'Trained on NSL-KDD, our XGBoost classifier identifies DoS, Probe, R2L, and U2R attacks across 41 network flow features.',
    path: '/network',
    img: 'https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=600&q=80',
  },
];

const STATS = [
  { value: '99.3%', label: 'Phishing Accuracy' },
  { value: '97.8%', label: 'Network F1-Score' },
  { value: '4', label: 'Detection Engines' },
  { value: 'SHAP+LIME', label: 'Explainability' },
];

export default function Landing() {
  return (
    <div className={styles.root}>
      {/* ── Hero ── */}
      <header className={styles.hero}>
        <div className={styles.heroText}>
          <div className={styles.eyebrow}>
            <Shield size={14} strokeWidth={2} />
            Capstone Research Project — B.Tech CSE
          </div>
          <h1 className={styles.heroTitle}>
            Adaptive Explainable
            <br />
            <span className={styles.accent}>Multi-Source</span>
            <br />
            Cyber Threat Detection
          </h1>
          <p className={styles.heroSub}>
            A unified framework combining DistilBERT, XGBoost, Isolation Forest
            and SHAP-LIME explainability to detect phishing emails, malicious URLs,
            anomalous logins, and network intrusions — from a single dashboard.
          </p>
          <div className={styles.heroActions}>
            <Link to="/dashboard" className="btn btn-primary">
              Open Dashboard <ArrowRight size={16} />
            </Link>
            <Link to="/fusion" className="btn btn-outline">
              Threat Fusion Engine
            </Link>
          </div>
        </div>

        <div className={styles.heroVisual}>
          <div className={styles.globeWrap}>
            <Globe size={400} />
          </div>
          <div className={styles.globeCaption}>Live threat intelligence network</div>
        </div>
      </header>

      {/* ── Stats strip ── */}
      <section className={styles.statsStrip}>
        {STATS.map(s => (
          <div key={s.label} className={styles.stat}>
            <span className={styles.statValue}>{s.value}</span>
            <span className={styles.statLabel}>{s.label}</span>
          </div>
        ))}
      </section>

      {/* ── SOC photo band ── */}
      <section className={styles.photoBand}>
        <img
          src="https://images.unsplash.com/photo-1573164713988-8665fc963095?w=1600&q=80"
          alt="Security operations center analysts monitoring screens"
          className={styles.photoFull}
          loading="lazy"
        />
        <div className={styles.photoOverlay}>
          <h2 className={styles.photoHeading}>
            Intelligence-led defence<br />at every layer of the stack
          </h2>
        </div>
      </section>

      {/* ── Detection modules grid ── */}
      <section className={styles.modules}>
        <div className={styles.sectionHead}>
          <h2 className={styles.sectionTitle}>Detection Modules</h2>
          <p className={styles.sectionSub}>Four specialised engines, each optimised for its threat domain.</p>
        </div>
        <div className={styles.moduleGrid}>
          {MODULES.map(m => (
            <Link key={m.title} to={m.path} className={styles.moduleCard}>
              <div className={styles.moduleImgWrap}>
                <img src={m.img} alt={m.title} className={styles.moduleImg} loading="lazy" />
                <div className={styles.moduleImgOverlay} />
              </div>
              <div className={styles.moduleBody}>
                <div className={styles.moduleIcon}>
                  <m.icon size={18} strokeWidth={1.8} />
                </div>
                <h3 className={styles.moduleTitle}>{m.title}</h3>
                <p className={styles.moduleDesc}>{m.desc}</p>
                <span className={styles.moduleLink}>
                  Analyse now <ArrowRight size={14} />
                </span>
              </div>
            </Link>
          ))}
        </div>
      </section>

      {/* ── Fusion section ── */}
      <section className={styles.fusionSection}>
        <div className={styles.fusionLeft}>
          <img
            src="https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=800&q=80"
            alt="Data analytics dashboard with charts"
            className={styles.fusionImg}
            loading="lazy"
          />
        </div>
        <div className={styles.fusionRight}>
          <div className={styles.eyebrow}><Zap size={14} /> Threat Fusion Engine</div>
          <h2 className={styles.fusionTitle}>All signals,<br />one verdict</h2>
          <p className={styles.fusionDesc}>
            Submit email content, a URL, login metadata, and network features simultaneously.
            Our fusion engine weighs outputs from all four ML models and returns a single
            composite risk score with prioritised remediation recommendations.
          </p>
          <Link to="/fusion" className="btn btn-primary">
            Launch Fusion Engine <ArrowRight size={16} />
          </Link>
        </div>
      </section>

      {/* ── Explainability section ── */}
      <section className={styles.xaiSection}>
        <div className={styles.sectionHead}>
          <h2 className={styles.sectionTitle}>Why did it flag this?</h2>
          <p className={styles.sectionSub}>Every prediction ships with a human-readable explanation powered by SHAP and LIME.</p>
        </div>
        <div className={styles.xaiGrid}>
          <div className={styles.xaiCard}>
            <img
              src="https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=600&q=80"
              alt="Data scientist reviewing model outputs"
              className={styles.xaiImg}
              loading="lazy"
            />
            <div className={styles.xaiText}>
              <h3>SHAP Values</h3>
              <p>Feature-level importance scores that show exactly which words, URL tokens, or network statistics drove the classification decision.</p>
            </div>
          </div>
          <div className={styles.xaiCard}>
            <img
              src="https://images.unsplash.com/photo-1504868584819-f8e8b4b6d7e3?w=600&q=80"
              alt="Machine learning model visualization"
              className={styles.xaiImg}
              loading="lazy"
            />
            <div className={styles.xaiText}>
              <h3>LIME Surrogate</h3>
              <p>Local interpretable model-agnostic explanations build a linear approximation around each prediction, making black-box models transparent.</p>
            </div>
          </div>
        </div>
        <div style={{ textAlign: 'center', marginTop: '2rem' }}>
          <Link to="/about" className="btn btn-outline">
            View Technical Details
          </Link>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className={styles.footer}>
        <div className={styles.footerInner}>
          <div className={styles.footerBrand}>
            <Shield size={20} />
            <span>CyberShield AI</span>
          </div>
          <p className={styles.footerText}>
            Adaptive Explainable Multi-Source Cyber Threat Detection Framework
            using DistilBERT, XGBoost, Isolation Forest and SHAP-LIME
          </p>
          <a
            href="https://github.com/harshabasava970-bot/adaptive-ai-cyber-threat"
            target="_blank"
            rel="noreferrer"
            className={styles.footerLink}
          >
            <Github size={16} /> View on GitHub
          </a>
        </div>
      </footer>
    </div>
  );
}
