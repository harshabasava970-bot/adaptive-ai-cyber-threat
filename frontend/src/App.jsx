import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Landing from './pages/Landing'
import Dashboard from './pages/Dashboard'
import Phishing from './pages/Phishing'
import UrlAnalyser from './pages/UrlAnalyser'
import LoginMonitor from './pages/LoginMonitor'
import Network from './pages/Network'
import ThreatFusion from './pages/ThreatFusion'
import Timeline from './pages/Timeline'
import Reports from './pages/Reports'
import Analytics from './pages/Analytics'
import About from './pages/About'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route element={<Layout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/phishing" element={<Phishing />} />
        <Route path="/url" element={<UrlAnalyser />} />
        <Route path="/login" element={<LoginMonitor />} />
        <Route path="/network" element={<Network />} />
        <Route path="/fusion" element={<ThreatFusion />} />
        <Route path="/timeline" element={<Timeline />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/about" element={<About />} />
      </Route>
    </Routes>
  )
}
