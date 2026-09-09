import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import morgan from 'morgan'
import jwt from 'jsonwebtoken'

const app = express()
const port = process.env.PORT || 4000
const secret = process.env.JWT_SECRET || 'dev-only-cybershield-secret'

app.use(helmet())
app.use(cors({
  origin(origin, callback) {
    if (isAllowedOrigin(origin)) return callback(null, true)
    callback(new Error(`Origin ${origin} not allowed by CORS`))
  },
  credentials: true
}))
app.use(express.json({ limit: '2mb' }))
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 250, standardHeaders: true }))
app.use(morgan('tiny'))

const now = () => new Date().toISOString()
const allowedOrigins = (process.env.CLIENT_ORIGIN || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean)
const isAllowedOrigin = origin => {
  if (!origin) return true
  return allowedOrigins.includes(origin) || /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0):\d+$/.test(origin)
}
const users = [{ id: 'usr-001', name: 'Jordan Lee', email: 'analyst@cybershield.ai', role: 'Security Analyst', password: 'demo' }]
const alerts = [
  { id: 'ALT-1048', title: 'Possible brute-force activity', description: '50 failed login attempts detected within 2 minutes against an admin route.', severity: 'Critical', source: 'Auth Gateway', timestamp: '2026-09-05T09:42:00Z', status: 'Investigating', analyst: 'Jordan Lee', action: 'Review authentication logs and enforce temporary rate limiting.' },
  { id: 'ALT-1047', title: 'Missing security headers', description: 'Content-Security-Policy and Permissions-Policy are not present on the assessed target.', severity: 'High', source: 'Scanner', timestamp: '2026-09-05T09:15:00Z', status: 'New', analyst: 'Unassigned', action: 'Deploy a restrictive header policy and verify in staging.' },
  { id: 'ALT-1046', title: 'Unusual outbound request pattern', description: 'A service made repeated requests to a newly observed external endpoint.', severity: 'Medium', source: 'Network Sensor', timestamp: '2026-09-05T08:58:00Z', status: 'New', analyst: 'Unassigned', action: 'Validate the service owner and inspect related request traces.' },
  { id: 'ALT-1045', title: 'Expired TLS certificate chain', description: 'A monitored endpoint returned an incomplete certificate chain during validation.', severity: 'High', source: 'TLS Monitor', timestamp: '2026-09-05T08:21:00Z', status: 'Resolved', analyst: 'Jordan Lee', action: 'Renew and deploy the complete certificate chain.' }
]
const events = [
  { time: '09:42:18', event: 'Multiple failed admin logins', source: '10.24.8.19', severity: 'Critical', status: 'Investigating' },
  { time: '09:35:06', event: 'CSP header absent', source: 'app.cybershield.dev', severity: 'High', status: 'Open' },
  { time: '09:16:44', event: 'Unusual API request burst', source: '172.16.4.21', severity: 'Medium', status: 'Review' },
  { time: '08:58:11', event: 'TLS certificate validated', source: 'portal.acme.test', severity: 'Low', status: 'Resolved' },
  { time: '08:41:29', event: 'New device sign-in', source: 'Jordan Lee', severity: 'Low', status: 'Resolved' },
  { time: '08:12:03', event: 'Sensitive endpoint accessed', source: '10.24.5.6', severity: 'High', status: 'Open' }
]
const vulnerabilities = [
  { id: 'VUL-001', name: 'Security Misconfiguration', severity: 'Critical', component: 'Public API gateway', description: 'Administrative routes expose verbose error responses and missing policy headers.', risk: 'Information disclosure and increased attack surface.', remediation: 'Apply a hardened header baseline and disable verbose production errors.', status: 'Open' },
  { id: 'VUL-002', name: 'Authentication Weaknesses', severity: 'High', component: 'Account recovery', description: 'Recovery flow lacks adaptive rate limiting for repeated requests.', risk: 'Account enumeration and abuse of recovery workflows.', remediation: 'Add throttling, generic responses, and step-up verification.', status: 'In progress' },
  { id: 'VUL-003', name: 'Broken Access Control', severity: 'High', component: 'Reporting service', description: 'Object-level authorization needs explicit ownership checks.', risk: 'Users could access reports outside their organization.', remediation: 'Enforce tenant and role checks at every report read/write boundary.', status: 'Open' },
  { id: 'VUL-004', name: 'Sensitive Data Exposure', severity: 'Medium', component: 'Audit exports', description: 'Exports include more metadata than the analyst workflow requires.', risk: 'Unnecessary exposure of operational details.', remediation: 'Minimize export fields and protect files with short-lived access links.', status: 'Accepted' }
]
const auditLogs = [
  { timestamp: '2026-09-05 09:43', user: 'Jordan Lee', ip: '10.24.8.19', action: 'Viewed alert', resource: 'ALT-1048', status: 'Success' },
  { timestamp: '2026-09-05 09:20', user: 'Jordan Lee', ip: '10.24.8.19', action: 'Started scanner', resource: 'portal.acme.test', status: 'Success' },
  { timestamp: '2026-09-05 08:41', user: 'Jordan Lee', ip: '10.24.8.19', action: 'Signed in', resource: 'Authentication', status: 'Success' },
  { timestamp: '2026-09-04 17:12', user: 'Admin User', ip: '10.24.2.4', action: 'Updated vulnerability', resource: 'VUL-003', status: 'Success' }
]
const reports = []

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  if (!token) return res.status(401).json({ message: 'Authentication required.' })
  try { req.user = jwt.verify(token, secret); next() } catch { return res.status(401).json({ message: 'Session expired. Please sign in again.' }) }
}
function audit(action, resource) { auditLogs.unshift({ timestamp: now().slice(0, 16).replace('T', ' '), user: 'Jordan Lee', ip: '10.24.8.19', action, resource, status: 'Success' }) }
function riskForUrl(target) { const unsafe = !target.startsWith('https://'); return { score: unsafe ? 72 : 28, level: unsafe ? 'High' : 'Low', indicators: unsafe ? ['Missing HTTPS', 'Transport integrity cannot be verified'] : ['HTTPS enabled', 'Stable domain structure', 'No suspicious redirect pattern observed'], explanation: unsafe ? 'The URL does not establish encrypted transport, so traffic may be exposed or altered.' : 'The URL passed the safe indicator checks in this demo environment.', recommendation: unsafe ? 'Enable HTTPS and redirect all plaintext traffic to the canonical secure URL.' : 'Continue monitoring headers, certificate health, and redirect changes.' } }

app.get('/api/health', (_, res) => res.json({ status: 'ok', service: 'CyberShield AI API' }))
app.post('/api/auth/login', (req, res) => { const { email, password } = req.body; const user = users.find(item => item.email === email); if (!user || password !== user.password) return res.status(401).json({ message: 'Invalid email or password. Demo: analyst@cybershield.ai / demo' }); const token = jwt.sign({ id: user.id, name: user.name, role: user.role, email: user.email }, secret, { expiresIn: '8h' }); audit('Signed in', 'Authentication'); res.json({ token, user: { id: user.id, name: user.name, role: user.role, email: user.email } }) })
app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }))
app.post('/api/auth/logout', auth, (_, res) => res.json({ message: 'Signed out.' }))
app.get('/api/dashboard', auth, (_, res) => res.json({ score: 84, critical: 1, high: 7, vulnerabilities: 12, suspiciousIps: 4, events: 1284, activeScans: 2, threatActivity: [{ day: 'Mon', value: 38 }, { day: 'Tue', value: 54 }, { day: 'Wed', value: 42 }, { day: 'Thu', value: 71 }, { day: 'Fri', value: 63 }, { day: 'Sat', value: 48 }, { day: 'Sun', value: 58 }], severity: [{ name: 'Critical', value: 8 }, { name: 'High', value: 24 }, { name: 'Medium', value: 42 }, { name: 'Low', value: 54 }], categories: [{ name: 'Auth', value: 42 }, { name: 'Network', value: 28 }, { name: 'Web', value: 21 }, { name: 'Config', value: 16 }] }))
app.get('/api/events', auth, (_, res) => res.json({ events }))
app.get('/api/alerts', auth, (_, res) => res.json({ alerts }))
app.patch('/api/alerts/:id', auth, (req, res) => { const alert = alerts.find(item => item.id === req.params.id); if (!alert) return res.status(404).json({ message: 'Alert not found.' }); alert.status = req.body.status || alert.status; if (req.body.analyst) alert.analyst = req.body.analyst; audit('Updated alert', alert.id); res.json({ alert }) })
app.post('/api/scans', auth, (req, res) => {
  const target = req.body.target?.trim()
  if (!target || !/^https?:\/\//i.test(target)) return res.status(400).json({ message: 'Enter a valid http or https target.' })
  const secure = target.startsWith('https://')
  audit('Started scanner', target)
  const result = {
    id: `SCN-${Date.now()}`, target, status: 'Completed', score: secure ? 86 : 54, level: secure ? 'Low' : 'Medium',
    findings: [
      { label: 'HTTPS availability', status: secure ? 'PASS' : 'WARNING', detail: secure ? 'Secure transport is available.' : 'Target does not use HTTPS.' },
      { label: 'Security headers', status: 'WARNING', detail: 'Content-Security-Policy should be reviewed.' },
      { label: 'Cookie configuration', status: 'PASS', detail: 'No insecure cookie flags detected in demo response.' },
      { label: 'TLS configuration', status: secure ? 'PASS' : 'N/A', detail: secure ? 'Certificate chain appears valid.' : 'TLS unavailable over HTTP.' }
    ],
    recommendations: ['Deploy a restrictive Content-Security-Policy.', 'Review redirect and cookie behavior in staging.']
  }
  res.status(201).json(result)
})
app.post('/api/url-analysis', auth, (req, res) => { const url = req.body.url?.trim(); if (!url || !/^https?:\/\//i.test(url)) return res.status(400).json({ message: 'Enter a valid URL including http:// or https://.' }); const result = { url, ...riskForUrl(url) }; audit('Analyzed URL', url); res.json(result) })
app.post('/api/ip-analysis', auth, (req, res) => { const ip = req.body.ip?.trim(); if (!/^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/.test(ip || '')) return res.status(400).json({ message: 'Enter a valid IPv4 address.' }); res.json({ ip, demo: true, score: ip === '10.24.8.19' ? 78 : 18, reputation: ip === '10.24.8.19' ? 'Needs review' : 'No concerns observed', region: 'Demo region', firstSeen: '2026-08-12', lastSeen: '2026-09-05 09:42', alerts: ip === '10.24.8.19' ? 6 : 0, events: ip === '10.24.8.19' ? ['50 failed login attempts', 'Admin route enumeration'] : ['No related security events'] }) })
app.post('/api/log-analysis', auth, (req, res) => { const text = req.body.content || ''; const count = (text.match(/failed|denied|unauthorized/gi) || []).length; const alert = { ...alerts[0], id: `ALT-${1050 + alerts.length}`, title: 'Possible brute-force activity', description: `${Math.max(50, count * 10)} failed authentication indicators detected in uploaded logs.`, timestamp: now(), status: 'New', source: 'Uploaded logs' }; alerts.unshift(alert); audit('Analyzed security log', 'Uploaded log'); res.status(201).json({ alert, message: 'Defensive analysis complete. Review the alert before taking action.' }) })
app.get('/api/vulnerabilities', auth, (_, res) => res.json({ vulnerabilities }))
app.patch('/api/vulnerabilities/:id', auth, (req, res) => { const item = vulnerabilities.find(v => v.id === req.params.id); if (!item) return res.status(404).json({ message: 'Vulnerability not found.' }); item.status = req.body.status || item.status; audit('Updated vulnerability', item.id); res.json({ vulnerability: item }) })
app.get('/api/reports', auth, (_, res) => res.json({ reports }))
app.post('/api/reports', auth, (req, res) => { const report = { id: `RPT-${Date.now()}`, target: req.body.target || 'Monitored environment', date: now().slice(0, 10), score: 84, level: 'Low', summary: 'The environment is broadly healthy with focused remediation needed for authentication controls and security headers.' }; reports.unshift(report); audit('Generated report', report.id); res.status(201).json({ report }) })
app.delete('/api/reports/:id', auth, (req, res) => { const index = reports.findIndex(r => r.id === req.params.id); if (index >= 0) reports.splice(index, 1); res.json({ message: 'Report deleted.' }) })
app.get('/api/audit-logs', auth, (_, res) => res.json({ logs: auditLogs }))
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ message: 'Something went wrong on the server.' }) })
app.listen(port, () => console.log(`CyberShield API listening on http://localhost:${port}`))
