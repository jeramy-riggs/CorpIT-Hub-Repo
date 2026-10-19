import React, { useState } from 'react';
import { CheckCircle2, XCircle, RefreshCw, Server, Database, Clock } from 'lucide-react';
import { useApi, formatDateTime, BASE_PATH } from '../hooks/useApi';

export default function SettingsPage() {
  const { data: health, refetch: refetchHealth } = useApi('/api/health');
  const { data: syncHistory, refetch: refetchSync } = useApi('/api/health/sync-history');
  const [oktaTest, setOktaTest] = useState(null);
  const [testing, setTesting] = useState(false);
  const [syncing, setSyncing] = useState(false);

  const testOkta = async () => {
    setTesting(true);
    setOktaTest(null);
    try {
      const res = await fetch(`${BASE_PATH}/api/health/okta-test`);
      const data = await res.json();
      setOktaTest(data);
    } catch (err) {
      setOktaTest({ connected: false, error: err.message });
    }
    setTesting(false);
  };

  const triggerSync = async () => {
    setSyncing(true);
    try {
      await fetch(`${BASE_PATH}/api/health/sync`, { method: 'POST' });
      refetchHealth();
      refetchSync();
    } catch { /* silent */ }
    setSyncing(false);
  };

  return (
    <div>
      <div className="page-header fade-in">
        <h2>Settings & Health</h2>
        <p>System status, Okta connectivity, and data sync management.</p>
      </div>

      <div className="grid-2 fade-in">
        {/* System Health */}
        <div className="panel">
          <div className="panel-header"><h3><Server size={16} /> System Health</h3></div>
          <div className="panel-body">
            {health && (
              <div className="detail-grid">
                <div className="detail-item">
                  <label>Status</label>
                  <span style={{ color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <CheckCircle2 size={14} /> Running
                  </span>
                </div>
                <div className="detail-item">
                  <label>Uptime</label>
                  <span>{Math.round(health.uptime / 60)} minutes</span>
                </div>
                <div className="detail-item">
                  <label>Cached Users</label>
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{health.cached?.users || 0}</span>
                </div>
                <div className="detail-item">
                  <label>Cached Apps</label>
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{health.cached?.applications || 0}</span>
                </div>
                <div className="detail-item">
                  <label>Last Sync</label>
                  <span>{formatDateTime(health.lastSync?.completed_at)}</span>
                </div>
                <div className="detail-item">
                  <label>Last Sync Status</label>
                  <span className={`badge ${health.lastSync?.status === 'completed' ? 'active' : 'locked'}`}>
                    {health.lastSync?.status || 'Never'}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Okta Connectivity */}
        <div className="panel">
          <div className="panel-header"><h3><Database size={16} /> Okta Connectivity</h3></div>
          <div className="panel-body">
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: 16 }}>
              Test the connection to your Okta org to verify API credentials.
            </p>

            <button className="btn primary" onClick={testOkta} disabled={testing}>
              {testing ? <><RefreshCw size={14} className="spin" /> Testing…</> : 'Test Okta Connection'}
            </button>

            {oktaTest && (
              <div style={{
                marginTop: 16, padding: 16, borderRadius: 10,
                background: oktaTest.connected ? 'var(--accent-green-soft)' : 'var(--accent-red-soft)',
                border: `1px solid ${oktaTest.connected ? 'var(--accent-green)' : 'var(--accent-red)'}`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600, marginBottom: 4 }}>
                  {oktaTest.connected ? <CheckCircle2 size={16} color="var(--accent-green)" /> : <XCircle size={16} color="var(--accent-red)" />}
                  {oktaTest.connected ? 'Connected' : 'Connection Failed'}
                </div>
                {oktaTest.connected ? (
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    Org: <strong>{oktaTest.org}</strong> ({oktaTest.subdomain})
                  </div>
                ) : (
                  <div style={{ fontSize: '0.85rem', color: 'var(--accent-red)' }}>{oktaTest.error}</div>
                )}
              </div>
            )}

            <div style={{ marginTop: 20 }}>
              <button className="btn" onClick={triggerSync} disabled={syncing}>
                <RefreshCw size={14} className={syncing ? 'spin' : ''} />
                {syncing ? 'Syncing…' : 'Trigger Full Sync'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Sync History */}
      <div className="panel fade-in" style={{ marginTop: 'var(--space-6)' }}>
        <div className="panel-header">
          <h3><Clock size={16} /> Recent Sync History</h3>
        </div>
        <div className="panel-body flush">
          <table className="data-table">
            <thead>
              <tr><th>Entity</th><th>Status</th><th>Records</th><th>Completed</th><th>Error</th></tr>
            </thead>
            <tbody>
              {(syncHistory || []).map((s, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 500, textTransform: 'capitalize' }}>{s.entity}</td>
                  <td>
                    <span className={`badge ${s.status === 'completed' ? 'active' : s.status === 'failed' ? 'locked' : 'staged'}`}>
                      {s.status}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{s.records}</td>
                  <td>{formatDateTime(s.completed_at)}</td>
                  <td style={{ color: 'var(--accent-red)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {s.error || '—'}
                  </td>
                </tr>
              ))}
              {(!syncHistory || syncHistory.length === 0) && (
                <tr><td colSpan={5} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>No sync history yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Okta Setup Guidance */}
      <div className="panel fade-in" style={{ marginTop: 'var(--space-6)' }}>
        <div className="panel-header"><h3>Okta Setup Guidance</h3></div>
        <div className="panel-body" style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', lineHeight: 1.7 }}>
          <h4 style={{ color: 'var(--text-primary)', marginBottom: 8 }}>Quick Start — API Token</h4>
          <ol style={{ paddingLeft: 20, marginBottom: 24 }}>
            <li>Log in to the Okta Admin Console.</li>
            <li>Go to <strong>Security → API → Tokens</strong>.</li>
            <li>Click <strong>Create Token</strong>, give it a name like "HelpDesk Dashboard".</li>
            <li>Copy the token value immediately (it is only shown once).</li>
            <li>Set <code>OKTA_API_TOKEN</code> in your <code>.env</code> file.</li>
            <li>Set <code>OKTA_AUTH_METHOD=token</code>.</li>
            <li>Restart the server and test connectivity from this page.</li>
          </ol>

          <h4 style={{ color: 'var(--text-primary)', marginBottom: 8 }}>Production — OAuth 2.0 Service App</h4>
          <ol style={{ paddingLeft: 20, marginBottom: 24 }}>
            <li>In Okta Admin Console, go to <strong>Applications → Create App Integration</strong>.</li>
            <li>Select <strong>API Services</strong>, give it a name.</li>
            <li>Under <strong>Client Credentials</strong>, select <strong>Public key / Private key</strong>.</li>
            <li>Generate a new key pair and download the private key PEM file.</li>
            <li>Note the <strong>Client ID</strong> and <strong>Key ID (kid)</strong>.</li>
            <li>Go to <strong>Okta Admin → Security → API → Trusted Origins</strong> if needed.</li>
            <li>Grant scopes: <code>okta.users.read</code>, <code>okta.apps.read</code>, <code>okta.logs.read</code>, <code>okta.groups.read</code>.</li>
            <li>Set <code>OKTA_CLIENT_ID</code>, <code>OKTA_PRIVATE_KEY_PATH</code>, <code>OKTA_KEY_ID</code>, and <code>OKTA_AUTH_METHOD=oauth</code> in your <code>.env</code>.</li>
          </ol>

          <h4 style={{ color: 'var(--text-primary)', marginBottom: 8 }}>Required Okta Scopes</h4>
          <p>The minimum scopes needed are: <code>okta.users.read</code>, <code>okta.apps.read</code>, <code>okta.logs.read</code>, <code>okta.groups.read</code>.</p>
          <p style={{ marginTop: 8 }}>For API token auth, the token inherits the permissions of the admin who created it. Use a Read-Only Admin role for least privilege.</p>
        </div>
      </div>
    </div>
  );
}
