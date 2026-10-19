import React, { useState, useEffect, useCallback } from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Users, AppWindow, ShieldAlert, Settings, Monitor,
  RefreshCw, Activity, Menu, X, Home
} from 'lucide-react';

import LandingPage from './pages/LandingPage';
import Dashboard from './pages/Dashboard';
import UsersPage from './pages/UsersPage';
import AppsPage from './pages/AppsPage';
import SecurityPage from './pages/SecurityPage';
import SettingsPage from './pages/SettingsPage';

var API = '/helpdesk';

function Sidebar(props) {
  var health = props.health;
  var syncing = props.syncing;
  var triggerSync = props.triggerSync;
  var sidebarOpen = props.sidebarOpen;
  var setSidebarOpen = props.setSidebarOpen;

  var formatSyncTime = function(iso) {
    if (!iso) return 'Never';
    var d = new Date(iso + 'Z');
    var now = new Date();
    var mins = Math.round((now - d) / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return mins + 'm ago';
    if (mins < 1440) return Math.round(mins / 60) + 'h ago';
    return d.toLocaleDateString();
  };

  var syncAge = health && health.lastSync && health.lastSync.completed_at
    ? (Date.now() - new Date(health.lastSync.completed_at + 'Z').getTime()) / 60000
    : Infinity;

  return (
    <aside className={'sidebar ' + (sidebarOpen ? 'open' : '')}>
      <div className="sidebar-logo">
        <h1>
          <span className="logo-icon">
            <ShieldAlert size={18} color="#fff" />
          </span>
          <span>
            Okta Dashboard
            <small>ITAM HelpDesk</small>
          </span>
        </h1>
      </div>
      <nav className="sidebar-nav">
        <NavLink to="/" end onClick={function(){ setSidebarOpen(false); }}>
          <Home size={18} /> Tool Hub
        </NavLink>
        <div className="sidebar-divider" />
        <NavLink to="/okta" end onClick={function(){ setSidebarOpen(false); }}>
          <LayoutDashboard size={18} /> Overview
        </NavLink>
        <NavLink to="/users" onClick={function(){ setSidebarOpen(false); }}>
          <Users size={18} /> Users
        </NavLink>
        <NavLink to="/apps" onClick={function(){ setSidebarOpen(false); }}>
          <AppWindow size={18} /> Applications
        </NavLink>
        <NavLink to="/security" onClick={function(){ setSidebarOpen(false); }}>
          <Activity size={18} /> Security & Logs
        </NavLink>
        <NavLink to="/settings" onClick={function(){ setSidebarOpen(false); }}>
          <Settings size={18} /> Settings
        </NavLink>
        <div className="sidebar-divider" />
        <a href="/IT_Inventory_App.html" style={{ textDecoration: 'none', color: 'inherit', display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px', fontSize: 14, opacity: 0.7 }}>
          <Monitor size={18} /> IT Command
        </a>
        <a href="/identity-diag.html" style={{ textDecoration: 'none', color: 'inherit', display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px', fontSize: 14, opacity: 0.7 }}>
          <Users size={18} /> Identity Diag
        </a>
        <a href="/zscaler-diag.html" style={{ textDecoration: 'none', color: 'inherit', display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px', fontSize: 14, opacity: 0.7 }}>
          <ShieldAlert size={18} /> Zscaler Diag
        </a>
        <div style={{ flex: 1 }} />
        <button onClick={triggerSync} disabled={syncing}>
          <RefreshCw size={18} className={syncing ? 'spin' : ''} />
          {syncing ? 'Syncing…' : 'Sync Now'}
        </button>
      </nav>
      <div className="sidebar-footer">
        {health && (
          <>
            <span style={{
              display: 'inline-block', width: 7, height: 7, borderRadius: '50%',
              background: syncAge > 60 ? 'var(--accent-amber)' : 'var(--accent-green)',
              marginRight: 6
            }} />
            Synced {formatSyncTime(health.lastSync ? health.lastSync.completed_at : null)}
            <br />
            {(health.cached ? health.cached.users : 0) || 0} users · {(health.cached ? health.cached.applications : 0) || 0} apps
          </>
        )}
      </div>
    </aside>
  );
}

function PagePills() {
  return (
    <div className="page-topbar">
      <div className="page-pills">
        <a href="/helpdesk/" className="page-pill" style={{marginRight:8,borderColor:'rgba(79,142,247,.3)',color:'#4f8ef7'}}>⌂ Home Base</a>
        <a href="/IT_Inventory_App.html" className="page-pill">IT Command</a>
        <a href="/identity-diag.html" className="page-pill">Identity Diag</a>
        <a href="/helpdesk/okta" className="page-pill active">Okta</a>
        <a href="/zscaler-diag.html" className="page-pill">Zscaler Diag</a>
        <a href="/sharepoint-governance-dashboard.html" className="page-pill">SharePoint Gov</a>
      </div>
    </div>
  );
}

function AppLayout() {
  var _health = useState(null);
  var health = _health[0]; var setHealth = _health[1];
  var _syncing = useState(false);
  var syncing = _syncing[0]; var setSyncing = _syncing[1];
  var _sidebar = useState(false);
  var sidebarOpen = _sidebar[0]; var setSidebarOpen = _sidebar[1];
  var location = useLocation();
  var isLanding = location.pathname === '/' || location.pathname === '';

  var fetchHealth = useCallback(function() {
    return fetch(API + '/api/health')
      .then(function(res){ return res.json(); })
      .then(function(data){ setHealth(data); })
      .catch(function(){});
  }, []);

  useEffect(function(){
    fetchHealth();
    var i = setInterval(fetchHealth, 60000);
    return function(){ clearInterval(i); };
  }, [fetchHealth]);

  var triggerSync = function() {
    setSyncing(true);
    fetch(API + '/api/health/sync', { method: 'POST' })
      .then(function(){ return fetchHealth(); })
      .catch(function(){})
      .then(function(){ setSyncing(false); });
  };

  if (isLanding) {
    return <Routes><Route path="/" element={<LandingPage />} /></Routes>;
  }

  return (
    <div className="app-layout">
      <button className="btn mobile-menu-toggle"
        onClick={function(){ setSidebarOpen(!sidebarOpen); }}>
        {sidebarOpen ? <X size={18} /> : <Menu size={18} />}
      </button>
      <Sidebar health={health} syncing={syncing} triggerSync={triggerSync}
        sidebarOpen={sidebarOpen} setSidebarOpen={setSidebarOpen} />
      <main className="main-content">
        <PagePills />
        <Routes>
          <Route path="/okta" element={<Dashboard />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/apps" element={<AppsPage />} />
          <Route path="/security" element={<SecurityPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </main>
    </div>
  );
}

function App() {
  return (
    <Router basename="/helpdesk">
      <AppLayout />
      <style>{`
.spin { animation: spin 1s linear infinite; }
.page-topbar{display:flex;align-items:center;justify-content:flex-end;padding:10px 24px;border-bottom:1px solid rgba(255,255,255,.07);position:sticky;top:0;z-index:40;background:var(--bg-primary,#0a0c10);}
.page-pills{display:flex;gap:8px;align-items:center;margin-left:auto;}
.page-pill{display:inline-flex;align-items:center;padding:7px 18px;border-radius:20px;font-size:12px;font-weight:600;cursor:pointer;text-decoration:none;transition:all .15s;background:rgba(255,255,255,.05);color:#8892a4;border:1px solid rgba(255,255,255,.07);white-space:nowrap;}
.page-pill:hover{background:rgba(255,255,255,.1);color:#e8ecf4;}
.page-pill.active{background:#4f8ef7;color:#fff;border-color:#4f8ef7;}
.page-pill.active:hover{background:#6fa3ff;}
      `}</style>
    </Router>
  );
}

export default App;
