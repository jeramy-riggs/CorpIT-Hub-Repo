import React, { useState } from 'react';
import { Shield, Search, X } from 'lucide-react';
import { useApi, timeAgo } from '../hooks/useApi';

export default function SecurityPage() {
  const [search, setSearch] = useState('');
  const { data: failedLogins } = useApi('/api/dashboard/failed-logins');
  const { data: topEvents } = useApi('/api/dashboard/top-events');
  const { data: lockouts } = useApi('/api/dashboard/recent-lockouts');
  const { data: inactiveUsers } = useApi('/api/users/filter/inactive');

  const filteredFailed = (failedLogins || []).filter(l =>
    !search || l.actor_login?.toLowerCase().includes(search.toLowerCase()) ||
    l.client_ip?.includes(search)
  );

  return (
    <div>
      <div className="page-header fade-in">
        <h2>Security & Activity Logs</h2>
        <p>Monitor sign-in failures, account lockouts, and suspicious activity patterns.</p>
      </div>

      {/* Quick Insights */}
      <div className="kpi-grid fade-in" style={{ marginBottom: 'var(--space-6)' }}>
        <div className="kpi-card red">
          <div className="kpi-label">Failed Logins (7d)</div>
          <div className="kpi-value">{failedLogins?.length || 0}</div>
        </div>
        <div className="kpi-card red">
          <div className="kpi-label">Locked Accounts</div>
          <div className="kpi-value">{lockouts?.length || 0}</div>
        </div>
        <div className="kpi-card amber">
          <div className="kpi-label">Inactive Users</div>
          <div className="kpi-value">{inactiveUsers?.length || 0}</div>
          <div className="kpi-sub">Active status, no login 30+ days</div>
        </div>
        <div className="kpi-card purple">
          <div className="kpi-label">Distinct Event Types</div>
          <div className="kpi-value">{topEvents?.length || 0}</div>
        </div>
      </div>

      <div className="grid-2">
        {/* Failed Logins Detail */}
        <div className="panel fade-in">
          <div className="panel-header">
            <h3><Shield size={16} /> Failed Sign-In Attempts (7 days)</h3>
            <span className="badge locked">{filteredFailed.length}</span>
          </div>
          <div style={{ padding: '12px 20px 0' }}>
            <div className="search-bar" style={{ marginBottom: 12 }}>
              <Search size={16} color="var(--text-muted)" />
              <input placeholder="Filter by user or IP…" value={search} onChange={e => setSearch(e.target.value)} />
              {search && <button className="btn" onClick={() => setSearch('')} style={{ padding: '2px 6px' }}><X size={12} /></button>}
            </div>
          </div>
          <div className="panel-body flush" style={{ maxHeight: 500, overflowY: 'auto' }}>
            <table className="data-table">
              <thead><tr><th>User</th><th>IP Address</th><th>Location</th><th>Time</th></tr></thead>
              <tbody>
                {filteredFailed.map((l, i) => (
                  <tr key={i}>
                    <td style={{ fontWeight: 500 }}>{l.actor_login}</td>
                    <td><code style={{ fontSize: '0.78rem', color: 'var(--accent-cyan)' }}>{l.client_ip}</code></td>
                    <td>{l.client_geo || '—'}</td>
                    <td>{timeAgo(l.published)}</td>
                  </tr>
                ))}
                {filteredFailed.length === 0 && (
                  <tr><td colSpan={4} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>No failed logins found</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Inactive Users List */}
        <div className="panel fade-in">
          <div className="panel-header">
            <h3>Inactive Users (30+ days no login)</h3>
            <span className="badge suspended">{inactiveUsers?.length || 0}</span>
          </div>
          <div className="panel-body flush" style={{ maxHeight: 500, overflowY: 'auto' }}>
            {!inactiveUsers?.length ? (
              <div className="empty-state"><h4>All clear</h4><p>All active users have logged in recently.</p></div>
            ) : (
              <table className="data-table">
                <thead><tr><th>User</th><th>Email</th><th>Last Login</th><th>Dept</th></tr></thead>
                <tbody>
                  {inactiveUsers.map(u => (
                    <tr key={u.id}>
                      <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{u.display_name}</td>
                      <td>{u.email}</td>
                      <td style={{ color: 'var(--accent-amber)' }}>{u.last_login ? timeAgo(u.last_login) : 'Never'}</td>
                      <td>{u.department || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* Top Event Types Table */}
      <div className="panel fade-in" style={{ marginTop: 'var(--space-6)' }}>
        <div className="panel-header">
          <h3>Event Type Frequency (7 days)</h3>
        </div>
        <div className="panel-body flush">
          <table className="data-table">
            <thead><tr><th>Event Type</th><th style={{ textAlign: 'right' }}>Count</th><th style={{ width: '40%' }}>Visual</th></tr></thead>
            <tbody>
              {(topEvents || []).map((e, i) => {
                const max = topEvents?.[0]?.count || 1;
                const pct = (e.count / max) * 100;
                return (
                  <tr key={i}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{e.event_type}</td>
                    <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{e.count}</td>
                    <td>
                      <div style={{
                        height: 8, borderRadius: 4, width: `${pct}%`,
                        background: `linear-gradient(90deg, var(--accent-blue), var(--accent-purple))`,
                        minWidth: 4
                      }} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
