export const RISK_COLORS = {
  Critical: '#C0392B',
  High:     '#A0522D',
  Medium:   '#C47C2B',
  Low:      '#788B70',
  Info:     '#5B7FA6',
  Unknown:  '#94a3b8',
}

export const RISK_BG = {
  Critical: '#FCF0EE',
  High:     '#FBF0EB',
  Medium:   '#FCF5EC',
  Low:      '#EFF3EE',
  Info:     '#EEF2F8',
}

/**
 * Maps a risk_level string to a CSS badge modifier class name.
 * Usage: `badge badge-${riskToStatus(level)}`
 */
export function riskToStatus(level = '') {
  const l = (level || '').toLowerCase();
  if (l === 'critical') return 'critical';
  if (l === 'high')     return 'high';
  if (l === 'medium')   return 'medium';
  if (l === 'low')      return 'low';
  return 'info';
}

export function scoreToPercent(score) {
  return Math.round((score || 0) * 100);
}

export function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}
