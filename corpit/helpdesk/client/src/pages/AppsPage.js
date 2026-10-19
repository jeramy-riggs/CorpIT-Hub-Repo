import React, { useState } from 'react';
import { Search, X, AppWindow, TrendingUp, TrendingDown, AlertCircle } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';
import { useApi } from '../hooks/useApi';

const COLORS = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#a78bfa', '#06b6d4', '#f472b6', '#84cc16'];
const tooltipStyle = {
  backgroundColor: '#1f2937', border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: 8, fontSize: '0.8rem', color: '#f1f5f9',
};

function AppIcon({ app }) {
  if (app.logo_url) return <img src={app.logo_url} alt="" className="app-icon" />;
  return (
    <span className="app-icon-placeholder">
      {(app.label || app.name || '?')[0].toUpperCase()}
    </span>
  );
}

export default function AppsPage() {
  const [search, setSearch] = useState('');
  const [tab, setTab] = useState('all');
  const { data: apps, loading } = useApi(`/api/apps${search ? `?search=${encodeURIComponent(search)}` : ''}`);
  const { data: usage } = useApi('/api/apps/usage-summary');

  const filteredApps = (apps || []).filter(a => {
    if (tab === 'unused') return a.assigned_user_count === 0;
    if (tab === 'top') return a.assigned_user_count >= 10;
    return true;
  });

  return (
    <div>
      <div className="page-header fade-in">
        <h2>SSO Applications</h2>
        <p>Application usage insights — identify the most-used, least-used, and potentially unused apps.</p>
      </div>

      {/* Usage Summary Cards */}
      {usage && (
        <div className="grid-3 fade-in" style={{ marginBottom: 'var(--space-6)' }}>
          {/* Most Used */}
          <div className="panel">
            <div className="panel-header">
              <h3><TrendingUp size={16} /> Most Assigned</h3>
            </div>
            <div className="panel-body flush">
              <table className="data-table">
                <thead><tr><th>App</th><th style={{ textAlign: 'right' }}>Users</th></tr></thead>
                <tbody>
                  {usage.mostUsed?.slice(0, 5).map(a => (
                    <tr key={a.id}>
                      <td style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <AppIcon app={a} />
                        <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{a.label}</span>
                      </td>
                      <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', color: 'var(--accent-green)' }}>
                        {a.assigned_user_count}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Least Used */}
          <div className="panel">
            <div className="panel-header">
              <h3><TrendingDown size={16} /> Least Assigned</h3>
            </div>
            <div className="panel-body flush">
              <table className="data-table">
                <thead><tr><th>App</th><th style={{ textAlign: 'right' }}>Users</th></tr></thead>
                <tbody>
                  {usage.leastUsed?.slice(0, 5).map(a => (
                    <tr key={a.id}>
                      <td style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <AppIcon app={a} />
                        <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{a.label}</span>
                      </td>
                      <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', color: 'var(--accent-amber)' }}>
                        {a.assigned_user_count}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Unused */}
          <div className="panel">
            <div className="panel-header">
              <h3><AlertCircle size={16} /> Unused (0 Assigned)</h3>
              <span className="badge suspended">{usage.unused?.length || 0}</span>
            </div>
            <div className="panel-body flush" style={{ maxHeight: 250, overflowY: 'auto' }}>
              {!usage.unused?.length ? (
                <div className="empty-state"><h4>None</h4><p>All apps have at least one user.</p></div>
              ) : (
                <table className="data-table">
                  <thead><tr><th>App</th><th>SSO Type</th></tr></thead>
                  <tbody>
                    {usage.unused.map(a => (
                      <tr key={a.id}>
                        <td style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <AppIcon app={a} />
                          <span>{a.label}</span>
                        </td>
                        <td>{a.sign_on_mode}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Charts Row */}
      {usage && (
        <div className="grid-2 fade-in" style={{ marginBottom: 'var(--space-6)' }}>
          {/* App Assignments Bar Chart */}
          <div className="panel">
            <div className="panel-header"><h3>Top 10 Apps by Assignment Count</h3></div>
            <div className="panel-body">
              <div className="chart-container">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={usage.mostUsed?.slice(0, 10)} layout="vertical" margin={{ left: 100 }}>
                    <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} />
                    <YAxis type="category" dataKey="label" tick={{ fill: '#94a3b8', fontSize: 11 }} width={100} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Bar dataKey="assigned_user_count" name="Users" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Sign-On Mode Breakdown */}
          <div className="panel">
            <div className="panel-header"><h3>SSO Mode Breakdown</h3></div>
            <div className="panel-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div className="chart-container" style={{ maxWidth: 320 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={usage.signOnModes || []} cx="50%" cy="50%" innerRadius={55} outerRadius={95}
                      paddingAngle={2} dataKey="count" nameKey="sign_on_mode"
                      label={({ sign_on_mode, percent }) => `${sign_on_mode} ${(percent * 100).toFixed(0)}%`}
                      labelLine={{ stroke: '#64748b' }}
                    >
                      {(usage.signOnModes || []).map((_, i) => (
                        <Cell key={i} fill={COLORS[i % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Full App Listing */}
      <div className="search-bar fade-in">
        <Search size={18} color="var(--text-muted)" />
        <input placeholder="Search applications…" value={search} onChange={e => setSearch(e.target.value)} />
        {search && <button className="btn" onClick={() => setSearch('')} style={{ padding: '4px 8px' }}><X size={14} /></button>}
      </div>

      <div className="filter-chips fade-in">
        {[['all', 'All Apps'], ['top', 'Top (10+)'], ['unused', 'Unused (0)']].map(([key, label]) => (
          <button key={key} className={`chip ${tab === key ? 'active' : ''}`} onClick={() => setTab(key)}>
            {label}
          </button>
        ))}
      </div>

      <div className="panel fade-in">
        <div className="panel-body flush">
          {loading ? (
            <div className="loading-center"><div className="spinner" /></div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Application</th>
                  <th>SSO Mode</th>
                  <th>Status</th>
                  <th style={{ textAlign: 'right' }}>Assigned Users</th>
                </tr>
              </thead>
              <tbody>
                {filteredApps.map(a => (
                  <tr key={a.id}>
                    <td style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <AppIcon app={a} />
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{a.label}</span>
                    </td>
                    <td>{a.sign_on_mode}</td>
                    <td><span className={`badge ${a.status === 'ACTIVE' ? 'active' : 'deprovisioned'}`}>{a.status}</span></td>
                    <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontWeight: 600,
                      color: a.assigned_user_count === 0 ? 'var(--accent-red)' : 'var(--text-primary)' }}>
                      {a.assigned_user_count}
                    </td>
                  </tr>
                ))}
                {filteredApps.length === 0 && (
                  <tr><td colSpan={4} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>No applications found</td></tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
