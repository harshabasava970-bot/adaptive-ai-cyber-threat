import styles from './KpiCard.module.css';
import { clsx } from 'clsx';

export default function KpiCard({ title, value, sub, icon: Icon, accent = false, loading = false }) {
  return (
    <div className={clsx(styles.card, accent && styles.accent)}>
      {Icon && (
        <div className={styles.iconWrap}>
          <Icon size={22} strokeWidth={1.6} />
        </div>
      )}
      <div className={styles.body}>
        {loading ? (
          <div className={styles.skeleton} />
        ) : (
          <span className={styles.value}>{value ?? '—'}</span>
        )}
        <span className={styles.title}>{title}</span>
        {sub && <span className={styles.sub}>{sub}</span>}
      </div>
    </div>
  );
}
