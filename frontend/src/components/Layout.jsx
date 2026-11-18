import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { useState } from 'react'
import {
  LayoutDashboard, Mail, Link2, User, Wifi, Zap,
  Clock, FileText, BarChart2, Info, Menu, X, Shield
} from 'lucide-react'
import styles from './Layout.module.css'

const NAV = [
  { label: 'Overview', items: [
    { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' }
  ]},
  { label: 'Detection', items: [
    { to: '/phishing', icon: Mail,         label: 'Phishing' },
    { to: '/url',      icon: Link2,        label: 'URL Analyser' },
    { to: '/login',    icon: User,         label: 'Login Monitor' },
    { to: '/network',  icon: Wifi,         label: 'Network' },
  ]},
  { label: 'Analysis', items: [
    { to: '/fusion',   icon: Zap,          label: 'Threat Fusion' },
    { to: '/timeline', icon: Clock,        label: 'Timeline' },
  ]},
  { label: 'Reports', items: [
    { to: '/reports',  icon: FileText,     label: 'Reports' },
    { to: '/analytics',icon: BarChart2,    label: 'Analytics' },
  ]},
  { label: 'Info', items: [
    { to: '/about',    icon: Info,         label: 'About' },
  ]},
]

export default function Layout() {
  const [open, setOpen] = useState(false)
  const location = useLocation()

  return (
    <div className={styles.shell}>
      {/* Sidebar */}
      <aside className={`${styles.sidebar} ${open ? styles.open : ''}`}>
        <div className={styles.brand}>
          <div className={styles.logo}><Shield size={18} /></div>
          <div>
            <div className={styles.brandName}>CyberShield AI</div>
            <div className={styles.brandSub}>Threat Detection Platform</div>
          </div>
        </div>

        <nav className={styles.nav}>
          {NAV.map(group => (
            <div key={group.label} className={styles.navGroup}>
              <div className={styles.navGroupLabel}>{group.label}</div>
              {group.items.map(({ to, icon: Icon, label }) => (
                <NavLink
                  key={to} to={to}
                  className={({ isActive }) =>
                    `${styles.navItem} ${isActive ? styles.active : ''}`}
                  onClick={() => setOpen(false)}
                >
                  <Icon size={15} />
                  <span>{label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className={styles.sidebarFooter}>
          <a
            href="https://cyber-threat-ai.streamlit.app"
            target="_blank" rel="noopener noreferrer"
            className={styles.legacyLink}
          >
            Legacy Dashboard ↗
          </a>
        </div>
      </aside>

      {/* Mobile header */}
      <header className={styles.mobileHeader}>
        <button className={styles.menuBtn} onClick={() => setOpen(o => !o)}>
          {open ? <X size={20} /> : <Menu size={20} />}
        </button>
        <div className={styles.mobileBrand}>
          <Shield size={16} style={{ color: '#B86F52' }} />
          <span>CyberShield AI</span>
        </div>
      </header>

      {/* Overlay */}
      {open && <div className={styles.overlay} onClick={() => setOpen(false)} />}

      {/* Main */}
      <main className={styles.main}>
        <Outlet />
      </main>
    </div>
  )
}
