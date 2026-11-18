import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || 'https://cyber-threat-api-4gms.onrender.com'

const client = axios.create({
  baseURL: `${API_BASE}/api/v1`,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// Unwrap axios response automatically
function req(promise) {
  return promise.then(r => r.data)
}

// Detection endpoints
export const detectPhishing = (emailText) =>
  req(client.post('/detect/phishing', { email_text: emailText, model: 'ensemble' }))

export const detectUrl = (url) =>
  req(client.post('/detect/url', { url }))

export const detectLogin = (payload) =>
  req(client.post('/detect/login', payload))

export const detectNetwork = (features) =>
  req(client.post('/detect/network', features))

export const fuseThreat = (payload) =>
  req(client.post('/detect/fuse', payload))

// Analytics endpoints
export const getRecentDetections = (limit = 50) =>
  req(client.get(`/analytics/recent?limit=${limit}`))

export const getThreatCounts = () =>
  req(client.get('/analytics/threat-counts'))

// Report download endpoints — return Blob
export const downloadCsv = () =>
  client.get('/reports/csv', { responseType: 'blob' }).then(r => r.data)

export const downloadPdf = () =>
  client.get('/reports/pdf', { responseType: 'blob' }).then(r => r.data)

// Health check
export const checkHealth = () =>
  axios.get(`${API_BASE}/health`, { timeout: 5000 }).then(r => r.data)
