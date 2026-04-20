// AI Firewall — dashboard data layer.
// Starts with design-provided fallbacks, then hydrates from live backend endpoints.

(function () {
  const API = ''; // same-origin; orchestrator serves /dashboard/ and API routes

  const FALLBACK = {
    nav: [
      { id: 'overview', label: 'Overview', icon: 'grid' },
      { id: 'traffic', label: 'Traffic', icon: 'activity' },
      { id: 'rules', label: 'Rules & Policies', icon: 'shield' },
      { id: 'threats', label: 'Threats', icon: 'alert', count: 0, tone: 'danger' },
      { id: 'logs', label: 'Logs', icon: 'file' },
      { id: 'devices', label: 'Devices', icon: 'cpu' },
      { id: 'reports', label: 'Reports', icon: 'chart' },
      { id: 'uploads', label: 'AI Intake', icon: 'upload', count: 'NEW', tone: 'info' },
    ],

    threats: [],
    rules: [],
    devices: [],
    countries: [],
    protocols: [
      { name: 'HTTPS / TLS 1.3', pct: 0, bytes: '0 KB' },
    ],
    reports: [],
    uploaded: [],
    logSamples: [],

    series: {
      throughput: new Array(48).fill(0),
      blocked: new Array(48).fill(0),
      latency: new Array(48).fill(10),
      sessions: new Array(48).fill(0),
    },

    kpis: {
      throughput: 0,
      blocked_24h: 0,
      active_sessions: 0,
      p95_latency: 0,
    },

    stats: { total: 0, allowed: 0, blocked: 0, threats: 0 },
  };

  const FW = Object.assign({}, FALLBACK);

  async function getJSON(path) {
    try {
      const r = await fetch(API + path, { cache: 'no-store' });
      if (!r.ok) throw new Error('http ' + r.status);
      return await r.json();
    } catch (err) {
      console.warn('[FW] fetch failed', path, err);
      return null;
    }
  }

  async function refreshOverview() {
    const data = await getJSON('/overview');
    if (!data) return;
    FW.series = data.series || FW.series;
    FW.threats = data.threats || FW.threats;
    FW.stats = data.stats || FW.stats;
    FW.kpis = data.kpis || FW.kpis;
    FW.logSamples = (data.recent_logs || []).map(mapLog);
  }

  async function refreshThreats() {
    const data = await getJSON('/threats');
    if (data && data.threats) FW.threats = data.threats;
  }

  async function refreshRules() {
    const data = await getJSON('/rules');
    if (!data) return;
    FW.rules = (data.rules || []).map(mapRule);
  }

  async function refreshDevices() {
    const data = await getJSON('/devices');
    if (data && data.devices) FW.devices = data.devices;
  }

  async function refreshProtocols() {
    const data = await getJSON('/protocols');
    if (data && data.protocols) FW.protocols = data.protocols;
  }

  async function refreshCountries() {
    const data = await getJSON('/countries');
    if (data && data.countries) FW.countries = data.countries;
  }

  async function refreshReports() {
    const data = await getJSON('/reports');
    if (data && data.reports) FW.reports = data.reports;
  }

  async function refreshUploads() {
    const data = await getJSON('/uploads');
    if (data && data.uploads) FW.uploaded = data.uploads;
  }

  async function refreshLogs() {
    const data = await getJSON('/stats');
    if (data && data.recent_logs) FW.logSamples = data.recent_logs.map(mapLog);
  }

  function mapLog(entry) {
    return {
      t: entry.t || entry.timestamp || '',
      level: entry.level || 'ALLOW',
      src: entry.src || entry.source || 'unknown',
      dst: entry.dst || entry.destination || 'unknown',
      proto: entry.proto || 'TCP',
      rule: entry.rule || 'AI',
      bytes: entry.bytes || '—',
      msg: entry.msg || entry.reason || '',
    };
  }

  // Map backend rule shape (action/match_type/value/priority) → design columns.
  function mapRule(r) {
    const actionMap = { allow: 'Allow', block: 'Block' };
    const categoryMap = {
      ip_src: 'Network',
      ip_dst: 'Network',
      port: 'Network',
      domain: 'Allowlist',
      keyword: 'WAF',
    };
    return {
      id: `R-${r.id}`,
      rawId: r.id,
      name: r.description || `${r.match_type} ${r.action} ${r.value}`,
      category: categoryMap[r.match_type] || 'Custom',
      action: actionMap[r.action] || r.action,
      targets: `${r.match_type}=${r.value}`,
      hits24h: r.hits24h || 0,
      enabled: !!r.enabled,
      updated: r.updated ? timeAgo(r.updated) : 'just now',
      raw: r,
    };
  }

  function timeAgo(iso) {
    try {
      const d = new Date(iso);
      const diff = (Date.now() - d.getTime()) / 1000;
      if (diff < 60) return `${Math.max(1, Math.floor(diff))}s ago`;
      if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
      if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
      return `${Math.floor(diff / 86400)}d ago`;
    } catch {
      return iso;
    }
  }

  async function refreshAll() {
    await Promise.all([
      refreshOverview(),
      refreshRules(),
      refreshDevices(),
      refreshProtocols(),
      refreshCountries(),
      refreshReports(),
      refreshUploads(),
    ]);
  }

  FW.api = {
    refreshAll,
    refreshOverview,
    refreshThreats,
    refreshRules,
    refreshDevices,
    refreshProtocols,
    refreshCountries,
    refreshReports,
    refreshUploads,
    refreshLogs,
    async addRule(body) {
      const r = await fetch(API + '/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      return r.json();
    },
    async deleteRule(rawId) {
      const r = await fetch(API + '/rules/' + encodeURIComponent(rawId), { method: 'DELETE' });
      return r.json().catch(() => ({}));
    },
    async toggleRule(rawId) {
      const r = await fetch(API + '/rules/' + encodeURIComponent(rawId) + '/toggle', { method: 'POST' });
      return r.json();
    },
    async triggerTest(type) {
      const r = await fetch(API + '/test_attack?type=' + encodeURIComponent(type), { method: 'POST' });
      return r.json().catch(() => ({}));
    },
    async listAllowlist() {
      const r = await fetch(API + '/allowlist', { cache: 'no-store' });
      return r.json().catch(() => ({ hosts: [] }));
    },
    async addAllowlist(host) {
      const r = await fetch(API + '/allowlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host }),
      });
      return r.json().catch(() => ({ ok: false }));
    },
    async deleteAllowlist(host) {
      const r = await fetch(API + '/allowlist/' + encodeURIComponent(host), { method: 'DELETE' });
      return r.json().catch(() => ({ ok: false }));
    },
    async upload(file, contentType) {
      const fd = new FormData();
      fd.append('content_type', contentType);
      fd.append('source_ip', 'dashboard');
      fd.append('destination_ip', 'ai-intake');
      fd.append('file', file);
      const r = await fetch(API + '/analyze_traffic', { method: 'POST', body: fd });
      return r.json().catch(() => ({}));
    },
  };

  window.FW = FW;
})();
