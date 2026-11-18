import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';
import { Shield, Mail, Link2, User, Network, AlertTriangle, CheckCircle, TrendingUp, ArrowRight } from 'lucide-react';
import KpiCard from '../components/KpiCard';
import { getRecentDetections, getThreatCounts, checkHealth } from '../lib/api';
import { riskToStatus, formatDate } from '../lib/riskUtils';
import styles from './Dashboard.module.css';

const COLORS = ['#B86F52', '#8B5A42', '#6B4226', '#4A2C1A', '#C4A882'];

const MODULE_LINKS = [
  { icon: Mail, label: 'Phishing Email', path: '/phishing', color: '#B86F52' },
  { icon: Link2, label: 'URL Analyser', path: '/url', color: '#8B5A42' },
  { icon: User, label: 'Login Monitor', path: '/login', color: '#6B4226' },
  { icon: Network, label: 'Network IDS', path: '/network', color: '#4A2C1A' },
];

export default function Dashboard() {
  const [recent, setRecent] = useState([]);
  const [threatCounts, setThreatCounts] = useState({});
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      getRecentDetections(20),
      getThreatCounts(),
      checkHealth(),
    ])
      .then(([r, t, h]) => {
        setRecent(r.detections || []);
        setThreatCounts(t.threat_counts || {});
        setHealth(h);
        setError(null);
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const totalDetections = recent.length;
  const threatCount = recent.filter(d => d.is_threat).length;
  const avgScore = recent.length
    ? (recent.reduce((s, d) => s + (d.risk_score || 0), 0) / recent.length).toFixed(1)
    : 0;

  // Threat type bar chart data
  const barData = Object.entries(threatCounts).map(([k, v]) => ({ name: k, count: v }));

  // Pie chart: threat vs clean
  const pieData = [
    { name: 'Threats', value: threatCount },
    { name: 'Clean', value: totalDetections - threatCount },
  ];

  // Recent 5 by type
  const byType = recent.reduce((acc, d) => {
    const t = d.threat_type || 'Unknown';
    acc[t] = (acc[t] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className={styles.root}>
      <div className="page-header">
        <div>
          <div className="page-eyebrow">Overview</div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-desc">Live threat detection metrics from the past 20 events.</p>
        </div>
        <div className={styles.healthBadge} data-ok={health?.status === 'healthy'}>
          {health ? (
            health.status === 'healthy'
              ? <><CheckCircle size={14} /> API Online</>
              : <><AlertTriangle size={14} /> API Degraded</>
          ) : '—'}
        </div>
      </div>

      {error && (
        <div className="alert alert-warning" style={{ marginBottom: '1.5rem' }}>
          <AlertTriangle size={15} /> Could not reach the backend API. Showing cached/empty data.
        </div>
      )}

      {/* KPI row */}
      <div className={styles.kpiRow}>
        <KpiCard title="Total Events" value={loading ? null : totalDetections} icon={Shield} loading={loading} />
        <KpiCard title="Threats Detected" value={loading ? null : threatCount} icon={AlertTriangle} accent={threatCount > 0} loading={loading} />
        <KpiCard title="Avg Risk Score" value={loading ? null : avgScore} icon={TrendingUp} loading={loading} />
        <KpiCard title="API Version" value={loading ? null : (health?.version || 'v1')} icon={CheckCircle} loading={loading} />
      </div>

      {/* Quick access */}
      <div className={styles.quickRow}>
        {MODULE_LINKS.map(m => (
          <Link key={m.path} to={m.path} className={styles.quickCard} style={{ '--accent': m.color }}>
            <div className={styles.quickIcon}>
              <m.icon size={20} strokeWidth={1.8} />
            </div>
            <span className={styles.quickLabel}>{m.label}</span>
            <ArrowRight size={14} className={styles.quickArrow} />
          </Link>
        ))}
      </div>

      {/* Charts */}
      {!loading && (
        <div className={styles.chartRow}>
          <div className={styles.chartCard}>
            <h3 className={styles.chartTitle}>Threat Distribution</h3>
            {barData.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={barData} barCategoryGap="30%">
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#8C7B70' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 11, fill: '#8C7B70' }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#FFFDF8', border: '1px solid #E8DDD4', borderRadius: 10, fontSize: 12 }}
                  />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                    {barData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className={styles.emptyChart}>No data yet — run some detections.</div>
            )}
          </div>

          <div className={styles.chartCard}>
            <h3 className={styles.chartTitle}>Threat vs Clean</h3>
            {totalDetections > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    <Cell fill="#B86F52" />
                    <Cell fill="#C4A882" />
                  </Pie>
                  <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12 }} />
                  <Tooltip contentStyle={{ background: '#FFFDF8', border: '1px solid #E8DDD4', borderRadius: 10, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className={styles.emptyChart}>No data yet.</div>
            )}
          </div>
        </div>
      )}

      {/* Recent detections table */}
      <div className={styles.tableCard}>
        <div className={styles.tableHeader}>
          <h3 className={styles.chartTitle}>Recent Detections</h3>
          <Link to="/timeline" className={styles.viewAll}>View all <ArrowRight size={13} /></Link>
        </div>
        {loading ? (
          <div className={styles.emptyChart}>Loading…</div>
        ) : recent.length === 0 ? (
          <div className={styles.emptyChart}>No detections recorded yet.</div>
        ) : (
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Risk Level</th>
                  <th>Score</th>
                  <th>Verdict</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {recent.slice(0, 10).map((d, i) => (
                  <tr key={i}>
                    <td><span className={styles.typeTag}>{d.threat_type || '—'}</span></td>
                    <td>
                      <span className={`badge badge-${riskToStatus(d.risk_level)}`}>{d.risk_level || '—'}</span>
                    </td>
                    <td>{d.risk_score != null ? d.risk_score.toFixed(1) : '—'}</td>
                    <td>{d.is_threat ? '⚠ Threat' : '✓ Clean'}</td>
                    <td className={styles.timeCell}>{d.timestamp ? formatDate(d.timestamp) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
