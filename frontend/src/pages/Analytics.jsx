import { useEffect, useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  LineChart, Line, CartesianGrid, PieChart, Pie, Legend,
} from 'recharts';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { getRecentDetections, getThreatCounts } from '../lib/api';
import { riskToStatus } from '../lib/riskUtils';
import KpiCard from '../components/KpiCard';
import { Shield, TrendingUp, Activity, BarChart2 } from 'lucide-react';
import styles from './Analytics.module.css';

const COLORS = ['#B86F52', '#8B5A42', '#6B4226', '#4A2C1A', '#C4A882', '#A07858'];

export default function Analytics() {
  const [detections, setDetections] = useState([]);
  const [threatCounts, setThreatCounts] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  function load() {
    setLoading(true);
    setError(null);
    Promise.all([getRecentDetections(50), getThreatCounts()])
      .then(([r, t]) => {
        setDetections(r.detections || []);
        setThreatCounts(t.threat_counts || {});
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }

  useEffect(() => { load(); }, []);

  // Derived metrics
  const total = detections.length;
  const threats = detections.filter(d => d.is_threat).length;
  const avgScore = total ? (detections.reduce((s, d) => s + (d.risk_score || 0), 0) / total).toFixed(1) : 0;
  const maxScore = total ? Math.max(...detections.map(d => d.risk_score || 0)).toFixed(1) : 0;

  // Bar chart: threat type counts
  const barData = Object.entries(threatCounts).map(([k, v]) => ({ name: k, count: v }));

  // Risk level distribution
  const levelCounts = detections.reduce((acc, d) => {
    const l = d.risk_level || 'Unknown';
    acc[l] = (acc[l] || 0) + 1;
    return acc;
  }, {});
  const levelData = Object.entries(levelCounts).map(([name, value]) => ({ name, value }));

  // Model usage
  const modelCounts = detections.reduce((acc, d) => {
    const m = d.model_name || 'Unknown';
    acc[m] = (acc[m] || 0) + 1;
    return acc;
  }, {});
  const modelData = Object.entries(modelCounts).map(([name, value]) => ({ name, value }));

  // Timeline: last N detections as a line
  const timelineData = detections.slice(-20).map((d, i) => ({
    idx: i + 1,
    score: d.risk_score ?? 0,
  }));

  return (
    <div className={styles.root}>
      <div className="page-header">
        <div>
          <div className="page-eyebrow">Analysis · Metrics</div>
          <h1 className="page-title">Analytics</h1>
          <p className="page-desc">Aggregated threat intelligence metrics from all detection events.</p>
        </div>
        <button className="btn btn-outline" onClick={load} style={{ fontSize: '0.82rem', padding: '0.5rem 1rem' }}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {error && (
        <div className="alert alert-warning" style={{ marginBottom: '1.5rem' }}>
          <AlertTriangle size={15} /> {error}
        </div>
      )}

      <div className={styles.kpiRow}>
        <KpiCard title="Total Detections" value={loading ? null : total} icon={Shield} loading={loading} />
        <KpiCard title="Threats Found" value={loading ? null : threats} icon={AlertTriangle} accent={threats > 0} loading={loading} />
        <KpiCard title="Avg Risk Score" value={loading ? null : avgScore} icon={TrendingUp} loading={loading} />
        <KpiCard title="Peak Risk Score" value={loading ? null : maxScore} icon={Activity} loading={loading} />
      </div>

      {!loading && (
        <div className={styles.chartGrid}>
          {/* Threat type bar */}
          <div className={styles.chartCard}>
            <h3 className={styles.chartTitle}>Detections by Threat Type</h3>
            {barData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={barData} barCategoryGap="30%">
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#8C7B70' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 11, fill: '#8C7B70' }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#FFFDF8', border: '1px solid #E8DDD4', borderRadius: 10, fontSize: 12 }} />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                    {barData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : <div className={styles.empty}>No data available.</div>}
          </div>

          {/* Risk score timeline */}
          <div className={styles.chartCard}>
            <h3 className={styles.chartTitle}>Risk Score Timeline (last 20)</h3>
            {timelineData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={timelineData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(232,221,212,0.8)" />
                  <XAxis dataKey="idx" tick={{ fontSize: 11, fill: '#8C7B70' }} axisLine={false} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#8C7B70' }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#FFFDF8', border: '1px solid #E8DDD4', borderRadius: 10, fontSize: 12 }} />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="#B86F52"
                    strokeWidth={2.5}
                    dot={{ fill: '#B86F52', r: 4 }}
                    activeDot={{ r: 6 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : <div className={styles.empty}>No timeline data.</div>}
          </div>

          {/* Risk level pie */}
          <div className={styles.chartCard}>
            <h3 className={styles.chartTitle}>Risk Level Distribution</h3>
            {levelData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={levelData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="value">
                    {levelData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                  </Pie>
                  <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: '#FFFDF8', border: '1px solid #E8DDD4', borderRadius: 10, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            ) : <div className={styles.empty}>No level data.</div>}
          </div>

          {/* Model usage */}
          <div className={styles.chartCard}>
            <h3 className={styles.chartTitle}>Model Usage</h3>
            {modelData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={modelData} layout="vertical" barCategoryGap="30%">
                  <XAxis type="number" tick={{ fontSize: 11, fill: '#8C7B70' }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: '#8C7B70' }} axisLine={false} tickLine={false} width={100} />
                  <Tooltip contentStyle={{ background: '#FFFDF8', border: '1px solid #E8DDD4', borderRadius: 10, fontSize: 12 }} />
                  <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                    {modelData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : <div className={styles.empty}>No model data.</div>}
          </div>
        </div>
      )}
    </div>
  );
}
