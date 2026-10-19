import React, { useState, useCallback, useEffect } from 'react';
import { Search, ChevronUp, ChevronDown, X, ExternalLink, ChevronLeft, ChevronRight } from 'lucide-react';
import { useApi, formatDate, timeAgo, statusColor } from '../hooks/useApi';

function UserDetailModal({ userId, onClose }) {
  const { data: user, loading } = useApi(userId ? `/api/users/${userId}` : null);
  if (!userId) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{loading ? 'Loading…' : user?.display_name || 'User Detail'}</h3>
          <button className="btn" onClick={onClose}><X size={16} /></button>
        </div>
        {loading || !user ? (
          <div className="loading-center"><div className="spinner" /></div>
        ) : (
          <div className="modal-body">
            <div className="detail-grid" style={{ marginBottom: 20 }}>
              <div className="detail-item"><label>Login</label><span>{user.login}</span></div>
              <div className="detail-item"><label>Email</label><span>{user.email}</span></div>
              <div className="detail-item"><label>Status</label><span className={`badge ${statusColor(user.status)}`}><span className="badge-dot" />{user.status}</span></div>
              <div className="detail-item"><label>Department</label><span>{user.department || '—'}</span></div>
              <div className="detail-item"><label>Title</label><span>{user.title || '—'}</span></div>
              <div className="detail-item"><label>Created</label><span>{formatDate(user.created)}</span></div>
              <div className="detail-item"><label>Last Login</label><span>{user.last_login ? timeAgo(user.last_login) : 'Never'}</span></div>
              <div className="detail-item"><label>Last PW Change</label><span>{formatDate(user.last_password_change)}</span></div>
              <div className="detail-item"><label>PW Expires (est.)</label>
                <span style={{ color: user.password_expiry_estimate && new Date(user.password_expiry_estimate) < new Date() ? 'var(--accent-red)' : undefined }}>
                  {formatDate(user.password_expiry_estimate)}
                </span>
              </div>
              <div className="detail-item"><label>Locked Out</label><span>{user.locked_out ? 'Yes' : 'No'}</span></div>
            </div>

            {/* Assigned Apps */}
            {user.apps?.length > 0 && (
              <>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: 8, color: 'var(--text-secondary)' }}>
                  Assigned Applications ({user.apps.length})
                </h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 20 }}>
                  {user.apps.map(a => (
                    <div key={a.app_id} style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      background: 'var(--bg-elevated)', borderRadius: 8, padding: '6px 12px',
                      fontSize: '0.82rem', color: 'var(--text-secondary)'
                    }}>
                      {a.logo_url ? <img src={a.logo_url} alt="" className="app-icon" style={{ width: 20, height: 20 }} /> :
                        <span className="app-icon-placeholder" style={{ width: 20, height: 20, fontSize: '0.6rem' }}>
                          {(a.label || '?')[0]}
                        </span>}
                      {a.label}
                    </div>
                  ))}
                </div>
              </>
            )}

            {/* Recent Activity */}
            {user.recentActivity?.length > 0 && (
              <>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: 8, color: 'var(--text-secondary)' }}>
                  Recent Activity
                </h4>
                <table className="data-table">
                  <thead><tr><th>Event</th><th>Outcome</th><th>IP</th><th>Time</th></tr></thead>
                  <tbody>
                    {user.recentActivity.slice(0, 10).map((e, i) => (
                      <tr key={i}>
                        <td>{e.display_message || e.event_type}</td>
                        <td><span className={`badge ${statusColor(e.outcome)}`}>{e.outcome}</span></td>
                        <td><code style={{ fontSize: '0.75rem' }}>{e.client_ip || '—'}</code></td>
                        <td>{timeAgo(e.published)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default function UsersPage() {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sort, setSort] = useState('display_name');
  const [order, setOrder] = useState('ASC');
  const [page, setPage] = useState(1);
  const [selectedUser, setSelectedUser] = useState(null);
  const limit = 30;

  const buildUrl = useCallback(() => {
    const params = new URLSearchParams({ sort, order, page, limit });
    if (search) params.set('search', search);
    if (statusFilter) params.set('status', statusFilter);
    return `/api/users?${params.toString()}`;
  }, [search, statusFilter, sort, order, page]);

  const { data, loading } = useApi(buildUrl());

  useEffect(() => { setPage(1); }, [search, statusFilter]);

  const toggleSort = (col) => {
    if (sort === col) setOrder(o => o === 'ASC' ? 'DESC' : 'ASC');
    else { setSort(col); setOrder('ASC'); }
  };

  const SortIcon = ({ col }) => {
    if (sort !== col) return null;
    return order === 'ASC' ? <ChevronUp size={13} /> : <ChevronDown size={13} />;
  };

  const statuses = ['', 'ACTIVE', 'LOCKED_OUT', 'SUSPENDED', 'DEPROVISIONED', 'STAGED', 'RECOVERY'];
  const totalPages = data ? Math.ceil(data.total / limit) : 1;

  return (
    <div>
      <div className="page-header fade-in">
        <h2>User Accounts</h2>
        <p>Browse, search, and inspect all Okta user accounts.</p>
      </div>

      {/* Search + Filters */}
      <div className="search-bar fade-in">
        <Search size={18} color="var(--text-muted)" />
        <input
          placeholder="Search by name, email, or login…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        {search && <button className="btn" onClick={() => setSearch('')} style={{ padding: '4px 8px' }}><X size={14} /></button>}
      </div>

      <div className="filter-chips fade-in">
        {statuses.map(s => (
          <button key={s} className={`chip ${statusFilter === s ? 'active' : ''}`}
            onClick={() => setStatusFilter(s)}>
            {s || 'All'}
          </button>
        ))}
      </div>

      {/* Users Table */}
      <div className="panel fade-in">
        <div className="panel-body flush">
          {loading ? (
            <div className="loading-center"><div className="spinner" /></div>
          ) : (
            <>
              <table className="data-table">
                <thead>
                  <tr>
                    <th onClick={() => toggleSort('display_name')}>Name <SortIcon col="display_name" /></th>
                    <th onClick={() => toggleSort('login')}>Login <SortIcon col="login" /></th>
                    <th onClick={() => toggleSort('status')}>Status <SortIcon col="status" /></th>
                    <th onClick={() => toggleSort('last_login')}>Last Login <SortIcon col="last_login" /></th>
                    <th onClick={() => toggleSort('last_password_change')}>Last PW Change <SortIcon col="last_password_change" /></th>
                    <th onClick={() => toggleSort('password_expiry_estimate')}>PW Expires <SortIcon col="password_expiry_estimate" /></th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {data?.users?.map(u => (
                    <tr key={u.id} style={{ cursor: 'pointer' }} onClick={() => setSelectedUser(u.id)}>
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.display_name}</td>
                      <td>{u.login}</td>
                      <td><span className={`badge ${statusColor(u.status)}`}><span className="badge-dot" />{u.status}</span></td>
                      <td>{u.last_login ? timeAgo(u.last_login) : <span style={{ color: 'var(--accent-amber)' }}>Never</span>}</td>
                      <td>{formatDate(u.last_password_change)}</td>
                      <td style={{
                        color: u.password_expiry_estimate && new Date(u.password_expiry_estimate) < new Date()
                          ? 'var(--accent-red)' : u.password_expiry_estimate && new Date(u.password_expiry_estimate) < new Date(Date.now() + 14 * 86400000)
                          ? 'var(--accent-amber)' : undefined
                      }}>
                        {formatDate(u.password_expiry_estimate)}
                      </td>
                      <td><ExternalLink size={14} color="var(--text-muted)" /></td>
                    </tr>
                  ))}
                  {data?.users?.length === 0 && (
                    <tr><td colSpan={7} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>No users found</td></tr>
                  )}
                </tbody>
              </table>

              {/* Pagination */}
              <div className="pagination">
                <span>Showing {((page - 1) * limit) + 1}–{Math.min(page * limit, data?.total || 0)} of {data?.total || 0}</span>
                <div className="pagination-btns">
                  <button className="btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
                    <ChevronLeft size={14} /> Prev
                  </button>
                  <button className="btn" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      <UserDetailModal userId={selectedUser} onClose={() => setSelectedUser(null)} />
    </div>
  );
}
