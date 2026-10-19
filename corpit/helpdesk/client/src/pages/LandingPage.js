import React from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert, Monitor, Wrench, Users, BarChart3, ArrowRight,
  LogOut, Search, LayoutDashboard, Radio, Wifi, UserCog, Trash2
} from 'lucide-react';

function ToolCard({ icon: Icon, title, description, to, href, color }) {
  var isExternal = !!href;
  var cardContent = (
    <>
      <div className="tool-card-icon" style={{ background: 'var(--accent-' + color + '-soft)', color: 'var(--accent-' + color + ')' }}>
        <Icon size={24} />
      </div>
      <div className="tool-card-body">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
      <div className="tool-card-arrow">
        <ArrowRight size={18} />
      </div>
    </>
  );
  if (isExternal) return <a href={href} className="tool-card">{cardContent}</a>;
  return <Link to={to} className="tool-card">{cardContent}</Link>;
}

function SectionHeader({ title, subtitle }) {
  return (
    <div className="landing-section-header">
      <h2 className="landing-section-title">{title}</h2>
      {subtitle && <p className="landing-section-sub">{subtitle}</p>}
    </div>
  );
}

export default function LandingPage() {
  var handleSignOut = function() {
    document.cookie = 'it_auth=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/';
    sessionStorage.removeItem('sso_user');
    window.location.href = '/login.html';
  };

  return (
    <div className="landing-page">
      <div className="landing-container">

        <header className="landing-header fade-in">
          <div className="landing-logo">
            <div className="landing-logo-icon">
              <ShieldAlert size={28} color="#fff" />
            </div>
            <div>
              <h1>CorpIT — Operations Hub</h1>
              <p>Internal Tools &amp; Asset Management Portal</p>
            </div>
          </div>
          <button className="landing-signout" onClick={handleSignOut}>
            <LogOut size={15} /> Sign Out
          </button>
        </header>

        {/* ── DIAGNOSTICS ─────────────────────────────── */}
        <section className="landing-section fade-in" style={{ animationDelay: '0.05s' }}>
          <SectionHeader title="Diagnostics" subtitle="Identity, access, and network troubleshooting tools" />
          <div className="tool-grid tool-grid-3">
            <ToolCard
              icon={BarChart3}
              title="Okta Dashboard"
              description="SSO application usage, user account health, password status, security events, and HelpDesk insights."
              to="/okta"
              color="blue"
            />
            <ToolCard
              icon={Search}
              title="Identity Diagnostics"
              description="AD account lockout analysis, password health, group memberships, Rapid7, FortiGate, and root cause diagnosis."
              href="/identity-diag.html"
              color="red"
            />
            <ToolCard
              icon={ShieldAlert}
              title="Zscaler Diagnostics"
              description="ZPA user access lookup, app segments, connector health, URL category lookup, security policy, and DLP dictionaries."
              href="/zscaler-diag.html"
              color="purple"
            />
          </div>
        </section>

        {/* ── OPERATIONS ──────────────────────────────── */}
        <section className="landing-section fade-in" style={{ animationDelay: '0.1s' }}>
          <SectionHeader title="Operations" subtitle="Asset management, provisioning, and governance tools" />
          <div className="tool-grid tool-grid-2">
            <ToolCard
              icon={Monitor}
              title="IT Asset Inventory"
              description="Production asset tracking, warranty management, Intune endpoints, patch health, and hardware lifecycle data."
              href="/IT_Inventory_App.html"
              color="green"
            />
            <ToolCard
              icon={UserCog}
              title="AD Provisioning"
              description="Create and modify Active Directory user accounts, set passwords, and manage group memberships for nrpi.local."
              href="/ad-provisioning.html"
              color="cyan"
            />
            <ToolCard
              icon={Trash2}
              title="AD Housekeeping"
              description="Identify and remediate stale accounts, disabled users, and AD cleanup tasks across nrpi.local."
              href="/ad-housekeeping.html"
              color="amber"
            />
            <ToolCard
              icon={LayoutDashboard}
              title="SharePoint Governance"
              description="Site lifecycle management, inactive site detection, external sharing audit, and storage governance."
              href="/sharepoint-governance-dashboard.html"
              color="cyan"
            />
          </div>
        </section>

        {/* ── DASHBOARDS ──────────────────────────────── */}
        <section className="landing-section fade-in" style={{ animationDelay: '0.15s' }}>
          <SectionHeader title="Dashboards" subtitle="Live operational views and monitoring" />
          <div className="tool-grid tool-grid-2">
            <ToolCard
              icon={Wifi}
              title="Live Presence"
              description="Real-time ZPA user activity grouped by location — see who's connected to the network right now."
              href="/live-presence.html"
              color="green"
            />
            <ToolCard
              icon={Radio}
              title="Meraki NOC"
              description="WiFi access point status, client counts, SSID breakdowns, and per-AP details across all office locations."
              href="/meraki-noc.html"
              color="teal"
            />
          </div>
        </section>

        <footer className="landing-footer fade-in" style={{ animationDelay: '0.2s' }}>
          CorpIT / ITAM &middot; Internal Use Only
        </footer>

      </div>
    </div>
  );
}
