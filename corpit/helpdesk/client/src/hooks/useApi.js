import { useState, useEffect, useCallback } from 'react';

// Base path for subpath deployment (matches nginx location block)
export const BASE_PATH = '/helpdesk';

export function useApi(url, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Prepend base path to relative API URLs
  const fullUrl = url && url.startsWith('/') ? `${BASE_PATH}${url}` : url;

  const refetch = useCallback(async () => {
    if (!fullUrl) { setLoading(false); return; }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(fullUrl);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setData(json);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
    // eslint-disable-next-line
  }, [fullUrl, ...deps]);

  useEffect(() => { refetch(); }, [refetch]);

  return { data, loading, error, refetch };
}

export function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

export function formatDateTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  });
}

export function timeAgo(iso) {
  if (!iso) return 'Never';
  const d = new Date(iso);
  const now = new Date();
  const mins = Math.round((now - d) / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
  if (mins < 43200) return `${Math.round(mins / 1440)}d ago`;
  return formatDate(iso);
}

export function statusColor(status) {
  const map = {
    ACTIVE: 'active', LOCKED_OUT: 'locked', SUSPENDED: 'suspended',
    DEPROVISIONED: 'deprovisioned', STAGED: 'staged', PROVISIONED: 'provisioned',
    RECOVERY: 'recovery', PASSWORD_EXPIRED: 'locked',
    SUCCESS: 'success', FAILURE: 'failure',
  };
  return map[status] || '';
}
