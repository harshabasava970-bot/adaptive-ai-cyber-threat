import { useState } from 'react';
import { FileText, Download, AlertTriangle, FileSpreadsheet } from 'lucide-react';
import { downloadCsv, downloadPdf } from '../lib/api';
import styles from './Reports.module.css';

export default function Reports() {
  const [csvLoading, setCsvLoading] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  async function handleCsv() {
    setCsvLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const blob = await downloadCsv();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'threat_detections.csv';
      a.click();
      URL.revokeObjectURL(url);
      setSuccess('CSV downloaded successfully.');
    } catch (e) {
      setError(e.message);
    } finally {
      setCsvLoading(false);
    }
  }

  async function handlePdf() {
    setPdfLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const blob = await downloadPdf();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'threat_report.pdf';
      a.click();
      URL.revokeObjectURL(url);
      setSuccess('PDF downloaded successfully.');
    } catch (e) {
      setError(e.message);
    } finally {
      setPdfLoading(false);
    }
  }

  return (
    <div className={styles.root}>
      <div className="page-header">
        <div>
          <div className="page-eyebrow">Reports · Export</div>
          <h1 className="page-title">Reports & Exports</h1>
          <p className="page-desc">
            Download a full history of all threat-detection events as a structured CSV
            or a formatted PDF report.
          </p>
        </div>
      </div>

      <div className={styles.hero}>
        <img
          src="https://images.unsplash.com/photo-1456324504439-367cee3b3c32?w=1200&q=80"
          alt="Business reports and analytics on desk"
          className={styles.heroImg}
          loading="lazy"
        />
        <div className={styles.heroOverlay} />
        <div className={styles.heroText}>
          <h2>Compliance-ready threat intelligence exports</h2>
          <p>All detections, scores, model names, and timestamps in one download.</p>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger" style={{ marginBottom: '1.5rem' }}>
          <AlertTriangle size={15} /> {error}
        </div>
      )}
      {success && (
        <div className="alert alert-success" style={{ marginBottom: '1.5rem' }}>
          ✓ {success}
        </div>
      )}

      <div className={styles.cardRow}>
        <div className={styles.reportCard}>
          <div className={styles.reportIcon}>
            <FileSpreadsheet size={28} strokeWidth={1.4} />
          </div>
          <div className={styles.reportBody}>
            <h3 className={styles.reportTitle}>CSV Export</h3>
            <p className={styles.reportDesc}>
              Structured comma-separated file with all detection events.
              Columns: threat_type, is_threat, risk_score, risk_level, model_name, algorithm, timestamp, and more.
              Import directly into Excel, pandas, or any BI tool.
            </p>
            <div className={styles.reportMeta}>
              <span>Format: .csv</span>
              <span>All events</span>
            </div>
          </div>
          <button
            className="btn btn-primary"
            onClick={handleCsv}
            disabled={csvLoading}
            style={{ marginTop: 'auto', alignSelf: 'flex-start' }}
          >
            {csvLoading ? 'Preparing…' : <><Download size={15} /> Download CSV</>}
          </button>
        </div>

        <div className={styles.reportCard}>
          <div className={styles.reportIcon}>
            <FileText size={28} strokeWidth={1.4} />
          </div>
          <div className={styles.reportBody}>
            <h3 className={styles.reportTitle}>PDF Report</h3>
            <p className={styles.reportDesc}>
              Formatted threat intelligence report with summary statistics,
              risk distribution charts, and detailed detection listings.
              Suitable for sharing with security teams and management.
            </p>
            <div className={styles.reportMeta}>
              <span>Format: .pdf</span>
              <span>All events</span>
            </div>
          </div>
          <button
            className="btn btn-primary"
            onClick={handlePdf}
            disabled={pdfLoading}
            style={{ marginTop: 'auto', alignSelf: 'flex-start' }}
          >
            {pdfLoading ? 'Generating…' : <><Download size={15} /> Download PDF</>}
          </button>
        </div>
      </div>

      <div className={styles.infoGrid}>
        <div className={styles.infoItem}>
          <h4>What's included</h4>
          <ul>
            <li>Full detection event history</li>
            <li>Risk scores and levels for each event</li>
            <li>Model name and algorithm used</li>
            <li>Inference time and probability scores</li>
            <li>Timestamps (UTC)</li>
          </ul>
        </div>
        <div className={styles.infoItem}>
          <h4>Recommended uses</h4>
          <ul>
            <li>SOC audit trail and incident documentation</li>
            <li>Academic research and analysis</li>
            <li>Performance benchmarking across time windows</li>
            <li>Regulatory compliance reporting</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
