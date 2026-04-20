/* global React, ReactDOM, Icon, OverviewPage, TrafficPage, RulesPage, ThreatsPage, LogsPage, DevicesPage, ReportsPage, UploadsPage */

const { useState, useEffect } = React;

const TWEAK_DEFAULTS = {
  theme: localStorage.getItem('fw_theme') || 'light',
  layout: localStorage.getItem('fw_layout') || 'sidebar',
  density: localStorage.getItem('fw_density') || 'normal',
};

const App = () => {
  const [page, setPage] = useState(() => localStorage.getItem('fw_page') || 'overview');
  const [theme, setTheme] = useState(TWEAK_DEFAULTS.theme);
  const [layout, setLayout] = useState(TWEAK_DEFAULTS.layout);
  const [density, setDensity] = useState(TWEAK_DEFAULTS.density);
  const [tweaksOpen, setTweaksOpen] = useState(false);
  const [liveTick, setLiveTick] = useState(0);

  // Backend-driven state
  const [series, setSeries] = useState(window.FW.series);
  const [threats, setThreats] = useState(window.FW.threats);
  const [rules, setRules] = useState(window.FW.rules);
  const [devices, setDevices] = useState(window.FW.devices);
  const [protocols, setProtocols] = useState(window.FW.protocols);
  const [countries, setCountries] = useState(window.FW.countries);
  const [reports, setReports] = useState(window.FW.reports);
  const [uploaded, setUploaded] = useState(window.FW.uploaded);
  const [logSamples, setLogSamples] = useState(window.FW.logSamples);
  const [kpis, setKpis] = useState(window.FW.kpis);

  const syncAll = React.useCallback(async () => {
    await window.FW.api.refreshAll();
    setSeries(window.FW.series);
    setThreats(window.FW.threats);
    setRules(window.FW.rules);
    setDevices(window.FW.devices);
    setProtocols(window.FW.protocols);
    setCountries(window.FW.countries);
    setReports(window.FW.reports);
    setUploaded(window.FW.uploaded);
    setLogSamples(window.FW.logSamples);
    setKpis(window.FW.kpis);
  }, []);

  // Initial load
  useEffect(() => { syncAll(); }, [syncAll]);

  // Periodic polling
  useEffect(() => {
    const id = setInterval(syncAll, 5000);
    return () => clearInterval(id);
  }, [syncAll]);

  // Live ticker (for animated KPIs)
  useEffect(() => {
    const id = setInterval(() => setLiveTick(t => t + 1), 1200);
    return () => clearInterval(id);
  }, []);

  useEffect(() => { localStorage.setItem('fw_page', page); }, [page]);
  useEffect(() => { localStorage.setItem('fw_theme', theme); document.documentElement.setAttribute('data-theme', theme); }, [theme]);
  useEffect(() => { localStorage.setItem('fw_layout', layout); document.documentElement.setAttribute('data-layout', layout); }, [layout]);
  useEffect(() => { localStorage.setItem('fw_density', density); document.documentElement.setAttribute('data-density', density); }, [density]);

  const onToggleRule = async (rawId) => {
    await window.FW.api.toggleRule(rawId);
    await window.FW.api.refreshRules();
    setRules(window.FW.rules);
  };

  const onDeleteRule = async (rawId) => {
    if (!confirm('Delete rule?')) return;
    await window.FW.api.deleteRule(rawId);
    await window.FW.api.refreshRules();
    setRules(window.FW.rules);
  };

  const onAddRule = async (body) => {
    const res = await window.FW.api.addRule(body);
    await window.FW.api.refreshRules();
    setRules(window.FW.rules);
    return res;
  };

  const refreshThreats = async () => {
    await window.FW.api.refreshThreats();
    setThreats(window.FW.threats);
  };
  const refreshLogs = async () => {
    await window.FW.api.refreshLogs();
    setLogSamples(window.FW.logSamples);
  };
  const refreshUploads = async () => {
    await window.FW.api.refreshUploads();
    setUploaded(window.FW.uploaded);
  };

  // Nav counts reflect live data
  const navWithCounts = window.FW.nav.map(n => {
    if (n.id === 'threats') return { ...n, count: threats.length, tone: threats.length ? 'danger' : undefined };
    if (n.id === 'uploads') return { ...n, count: uploaded.length || 'NEW', tone: 'info' };
    if (n.id === 'rules') return { ...n, count: rules.length };
    return n;
  });

  const [searchQuery, setSearchQuery] = useState('');

  const renderPage = () => {
    // Filter logic for pages that support it
    const filterLogs = (logs) => {
      if (!searchQuery) return logs;
      const q = searchQuery.toLowerCase();
      return logs.filter(l => 
        (l.src + l.dst + l.msg + l.rule + l.proto).toLowerCase().includes(q)
      );
    };

    switch (page) {
      case 'overview': return <OverviewPage series={series} threats={threats} countries={countries} kpis={kpis} logSamples={filterLogs(logSamples)} liveTick={liveTick}/>;
      case 'traffic':  return <TrafficPage series={series} protocols={protocols} kpis={kpis} logSamples={filterLogs(logSamples)}/>;
      case 'rules':    return <RulesPage rules={rules} onToggle={onToggleRule} onDelete={onDeleteRule} onAdd={onAddRule} onRefresh={syncAll}/>;
      case 'threats':  return <ThreatsPage threats={threats} kpis={kpis} onRefresh={refreshThreats}/>;
      case 'logs':     return <LogsPage logSamples={filterLogs(logSamples)} onRefresh={refreshLogs}/>;
      case 'devices':  return <DevicesPage devices={devices} onRefresh={syncAll}/>;
      case 'reports':  return <ReportsPage reports={reports} onRefresh={syncAll}/>;
      case 'uploads':  return <UploadsPage uploaded={uploaded} onRefresh={refreshUploads}/>;
      default: return null;
    }
  };

  const curNav = navWithCounts.find(n => n.id === page);

  return (
    <div className="app" data-screen-label={curNav?.label}>
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"/>
          <div className="brand-name">AI Firewall</div>
          <div className="brand-env">FYP</div>
        </div>
        <div className="nav-section">
          <div className="nav-label">Monitoring</div>
          {navWithCounts.slice(0, 5).map(n => (
            <NavItem key={n.id} nav={n} active={page === n.id} onClick={() => setPage(n.id)}/>
          ))}
        </div>
        <div className="nav-section">
          <div className="nav-label">Infrastructure</div>
          {navWithCounts.slice(5).map(n => (
            <NavItem key={n.id} nav={n} active={page === n.id} onClick={() => setPage(n.id)}/>
          ))}
        </div>
        <div className="sidebar-footer">
          <div className="avatar">FY</div>
          <div className="who">
            <div className="n">Operator</div>
            <div className="r">Admin · local</div>
          </div>
          <button className="btn btn-ghost btn-icon btn-sm" style={{ marginLeft: 'auto' }} onClick={() => setTweaksOpen(true)}>
            <Icon name="settings"/>
          </button>
        </div>
      </aside>

      <div className="topbar-alt">
        <div className="brand">
          <div className="brand-mark"/>
          <div className="brand-name">AI Firewall</div>
          <div className="brand-env">FYP</div>
        </div>
        <div className="tnav">
          {navWithCounts.map(n => (
            <NavItem key={n.id} nav={n} active={page === n.id} onClick={() => setPage(n.id)} compact/>
          ))}
        </div>
      </div>

      <main className="main">
        <div className="topbar">
          <div className="crumbs">
            <span>AI Firewall</span>
            <span className="sep">/</span>
            <span className="cur">{curNav?.label}</span>
          </div>
          
          <div className="search" style={{ marginLeft: '24px', marginRight: 'auto' }}>
            <Icon name="search" className="s-ic"/>
            <input 
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search rules, IPs, events, devices…"
            />
            <span className="kbd">⌘K</span>
          </div>

          <div className="top-actions">
            <button className="btn btn-ghost btn-icon" onClick={syncAll} title="Refresh">
              <Icon name="refresh"/>
            </button>
            <button className="btn btn-ghost btn-icon" title="Tweaks" onClick={() => setTweaksOpen(o => !o)}>
              <Icon name="sliders"/>
            </button>
          </div>
        </div>

        <div className="content">{renderPage()}</div>
      </main>

      <div className={`tweaks ${tweaksOpen ? 'open' : ''}`}>
        <div className="th">
          Tweaks
          <button className="btn btn-ghost btn-sm btn-icon" onClick={() => setTweaksOpen(false)}>
            <Icon name="close"/>
          </button>
        </div>
        <div className="tb">
          <div className="tweak-row">
            <span className="lbl">Theme</span>
            <Segmented value={theme} onChange={setTheme} options={[['light','Light'],['dark','Dark']]}/>
          </div>
          <div className="tweak-row">
            <span className="lbl">Layout</span>
            <Segmented value={layout} onChange={setLayout} options={[['sidebar','Sidebar'],['topbar','Topbar']]}/>
          </div>
          <div className="tweak-row">
            <span className="lbl">Density</span>
            <Segmented value={density} onChange={setDensity} options={[['compact','Compact'],['normal','Normal'],['cozy','Cozy']]}/>
          </div>
        </div>
      </div>
    </div>
  );
};

const NavItem = ({ nav, active, onClick, compact }) => (
  <button className="nav-item" aria-current={active ? 'page' : undefined} onClick={onClick} style={compact ? { padding: '6px 10px' } : {}}>
    <Icon name={nav.icon} size={16}/>
    <span>{nav.label}</span>
    {nav.count != null && (
      <span className={`nav-count ${nav.tone === 'danger' ? 'danger' : nav.tone === 'warn' ? 'warn' : ''}`}>
        {nav.count}
      </span>
    )}
  </button>
);

const Segmented = ({ value, onChange, options }) => (
  <div className="segmented">
    {options.map(([v, label]) =>
      <button key={v} aria-pressed={value === v} onClick={() => onChange(v)}>{label}</button>
    )}
  </div>
);

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
