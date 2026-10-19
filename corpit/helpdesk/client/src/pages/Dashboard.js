import React from 'react';
import {
  Users, UserCheck, Lock, AlertTriangle, AppWindow, KeyRound,
  ShieldOff, UserX, Clock, Activity
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area, CartesianGrid
} from 'recharts';
import { useApi, formatDate, formatDateTime, statusColor, timeAgo } from '../hooks/useApi';

const COLORS = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#a78bfa', '#06b6d4', '#f472b6', '#84cc16'];

function KpiCard({ icon: Icon, label, value, sub, color = 'blue', delay = 0 }) {
  return (
    <div className={`kpi-card ${color} fade-in`} style={{ animationDelay: `${delay}s` }}>
      <div className="kpi-icon"><Icon size={18} /></div>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value ?? '—'}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}

const chartTooltipStyle = {
  backgroundColor: '#1f2937',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: 8,
  fontSize: '0.8rem',
  color: '#f1f5f9',
};

export default function Dashboard() {
  const { data: summary, loading } = useApi('/api/dashboard/summary');
  const { data: lockouts } = useApi('/api/dashboard/recent-lockouts');
  const { data: pwExpiring } = useApi('/api/dashboard/pw-expiring');
  const { data: loginTrend } = useApi('/api/dashboard/login-trend');
  const { data: topEvents } = useApi('/api/dashboard/top-events');
  const { data: failedLogins } = useApi('/api/dashboard/failed-logins');

  if (loading || !summary) {
    return <div className="loading-center"><div className="spinner" /></div>;
  }

  const userStatusData = [
    { name: 'Active', value: summary.activeUsers },
    { name: 'Locked', value: summary.lockedOut },
    { name: 'Suspended', value: summary.suspended },
    { name: 'Deprovisioned', value: summary.deprovisioned },
  ].filter(d => d.value > 0);

  return (
    <div>
      <div className="page-header fade-in">
        <h2>Okta Dashboard</h2>
        <p>Real-time view of your Okta environment — users, apps, and security events.</p>
      </div>

      {/* ── KPI Cards ────────────────────────────── */}
      <div className="kpi-grid">
        <KpiCard icon={Users} label="Total Users" value={summary.totalUsers} color="blue" delay={0.03} />
        <KpiCard icon={UserCheck} label="Active Users" value={summary.activeUsers} color="green" delay={0.06} />
        <KpiCard icon={Lock} label="Locked Out" value={summary.lockedOut} color="red" delay={0.09}
          sub={summary.lockedOut > 0 ? 'Action needed' : 'All clear'} />
        <KpiCard icon={KeyRound} label="PW Expiring Soon" value={summary.pwExpiringSoon} color="amber" delay={0.12}
          sub="Next 14 days" />
        <KpiCard icon={ShieldOff} label="PW Expired" value={summary.pwExpired} color="red" delay={0.15} />
        <KpiCard icon={AppWindow} label="SSO Apps" value={summary.totalApps} color="purple" delay={0.18} />
        <KpiCard icon={UserX} label="Inactive Users" value={summary.inactiveUsers} color="amber" delay={0.21}
          sub="No login in 30+ days" />
        <KpiCard icon={AlertTriangle} label="Failed Logins (24h)" value={summary.failedLogins24h} color="red" delay={0.24} />
      </div>

      {/* ── Charts Row ───────────────────────────── */}
      <div className="grid-2" style={{ marginBottom: 'var(--space-6)' }}>
        {/* Login Trend */}
        <div className="panel fade-in fade-in-d1">
          <div className="panel-header">
            <h3><Activity size={16} /> Login Activity (7 days)</h3>
          </div>
          <div className="panel-body">
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={loginTrend || []}>
                  <defs>
                    <linearGradient id="gSuccess" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22c55e" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gFailure" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="day" tick={{ fill: '#64748b', fontSize: 12 }}
                    tickFormatter={v => new Date(v + 'T00:00').toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 12 }} />
                  <Tooltip contentStyle={chartTooltipStyle} />
                  <Area type="monotone" dataKey="success" name="Successful" stroke="#22c55e" fill="url(#gSuccess)" strokeWidth={2} />
                  <Area type="monotone" dataKey="failure" name="Failed" stroke="#ef4444" fill="url(#gFailure)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* User Status Breakdown */}
        <div className="panel fade-in fade-in-d2">
          <div className="panel-header">
            <h3><Users size={16} /> User Status Breakdown</h3>
          </div>
          <div className="panel-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div className="chart-container" style={{ maxWidth: 300 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={userStatusData} cx="50%" cy="50%" innerRadius={60} outerRadius={100}
                    paddingAngle={3} dataKey="value" nameKey="name"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    labelLine={{ stroke: '#64748b' }}
                  >
                    {userStatusData.map((_, i) => (
                      <Cell key={i} fill={COLORS[i % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={chartTooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      {/* ── Action Panels Row ────────────────────── */}
      <div className="grid-2">
        {/* Locked Out Users */}
        <div className="panel fade-in fade-in-d3">
          <div className="panel-header">
            <h3><Lock size={16} /> Locked Out Users</h3>
            <span className="badge locked">{lockouts?.length || 0}</span>
          </div>
          <div className="panel-body flush">
            {!lockouts?.length ? (
              <div className="empty-state"><h4>No lockouts</h4><p>All users can sign in normally.</p></div>
            ) : (
              <table className="data-table">
                <thead><tr><th>User</th><th>Email</th><th>Since</th></tr></thead>
                <tbody>
                  {lockouts.map(u => (
                    <tr key={u.id}>
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.display_name}</td>
                      <td>{u.email}</td>
                      <td>{timeAgo(u.status_changed)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Passwords Expiring Soon */}
        <div className="panel fade-in fade-in-d4">
          <div className="panel-header">
            <h3><KeyRound size={16} /> Passwords Expiring Soon</h3>
            <span className="badge suspended">{pwExpiring?.length || 0}</span>
          </div>
          <div className="panel-body flush">
            {!pwExpiring?.length ? (
              <div className="empty-state"><h4>All clear</h4><p>No passwords expiring in the warning window.</p></div>
            ) : (
              <table className="data-table">
                <thead><tr><th>User</th><th>Last Changed</th><th>Expires</th></tr></thead>
                <tbody>
                  {pwExpiring.map(u => (
                    <tr key={u.id}>
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.display_name}</td>
                      <td>{formatDate(u.last_password_change)}</td>
                      <td style={{ color: 'var(--accent-amber)' }}>{formatDate(u.password_expiry_estimate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* ── Top Events + Recent Failed Logins ───── */}
      <div className="grid-2" style={{ marginTop: 'var(--space-6)' }}>
        <div className="panel fade-in">
          <div className="panel-header">
            <h3><Activity size={16} /> Top Event Types (7 days)</h3>
          </div>
          <div className="panel-body">
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={(topEvents || []).slice(0, 8)} layout="vertical" margin={{ left: 120 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                  <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} />
                  <YAxis type="category" dataKey="event_type" tick={{ fill: '#94a3b8', fontSize: 11 }} width={120}
                    tickFormatter={v => v.split('.').slice(-2).join('.')} />
                  <Tooltip contentStyle={chartTooltipStyle} />
                  <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="panel fade-in">
          <div className="panel-header">
            <h3><ShieldOff size={16} /> Recent Failed Logins</h3>
          </div>
          <div className="panel-body flush" style={{ maxHeight: 340, overflowY: 'auto' }}>
            {!failedLogins?.length ? (
              <div className="empty-state"><h4>No recent failures</h4></div>
            ) : (
              <table className="data-table">
                <thead><tr><th>User</th><th>IP</th><th>Location</th><th>Time</th></tr></thead>
                <tbody>
                  {failedLogins.slice(0, 15).map((l, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 500 }}>{l.actor_login}</td>
                      <td><code style={{ fontSize: '0.78rem', color: 'var(--accent-cyan)' }}>{l.client_ip}</code></td>
                      <td>{l.client_geo || '—'}</td>
                      <td>{timeAgo(l.published)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* Sync timestamp */}
      <div style={{ textAlign: 'center', marginTop: 'var(--space-8)', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
        <Clock size={13} style={{ verticalAlign: -2, marginRight: 4 }} />
        Last sync: {summary.lastSync ? formatDateTime(summary.lastSync) : 'Never'} · Data refreshes automatically every 30 minutes
      </div>
    </div>
  );
}
