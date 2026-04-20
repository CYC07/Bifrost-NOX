/* global React, Icon, Sparkline, Dot, Badge, SevBadge, fmt, Legend */

// ====== Traffic ======
const TrafficPage = ({ series, protocols, kpis, logSamples }) => {
  const safe = series || { throughput: [], blocked: [] };
  const top = (logSamples || []).slice(0, 8);
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Traffic</h1>
          <div className="sub">Live flow inspection · MITM proxy + deep content analysis</div>
        </div>
        <div className="toolbar">
          <div className="filters">
            {['Live', '1h', '24h', '7d'].map((t, i) =>
              <button key={t} className="filter-pill" aria-pressed={i === 0}>{t}</button>
            )}
          </div>
          <button className="btn" onClick={() => window.FW.api.refreshAll()}>
            <Icon name="refresh"/>Refresh
          </button>
        </div>
      </div>

      <div className="grid g-4" style={{ marginBottom: 16 }}>
        <StatCard label="Throughput" value={(kpis?.throughput || 0).toString()} unit="ev/s" delta="live" tone="flat" live/>
        <StatCard label="Allowed" value={fmt.num(kpis?.active_sessions || 0)} delta="" tone="up"/>
        <StatCard label="Blocked" value={fmt.num(kpis?.blocked_24h || 0)} delta="" tone="up"/>
        <StatCard label="p95 Latency" value={(kpis?.p95_latency || 0).toString()} unit="ms" delta="" tone="flat"/>
      </div>

      <div className="grid g-12-8" style={{ marginBottom: 16 }}>
        <div className="card">
          <div className="card-head">
            <div>
              <h3>Throughput</h3>
              <div className="sub">Events/interval · 3s resolution</div>
            </div>
            <div className="hstack">
              <Legend color="var(--ink-2)" label="Total" val={fmt.num(safe.throughput.reduce((a, b) => a + b, 0))}/>
              <Legend color="var(--danger)" label="Blocked" val={fmt.num(safe.blocked.reduce((a, b) => a + b, 0))}/>
            </div>
          </div>
          <div className="card-body" style={{ padding: '14px 10px' }}>
            <Sparkline data={safe.throughput} color="var(--ink-2)" height={160}/>
            <Sparkline data={safe.blocked} color="var(--danger)" height={80}/>
          </div>
        </div>
        <div className="card">
          <div className="card-head">
            <h3>Protocol breakdown</h3>
            <span className="muted" style={{ fontSize: 11 }}>observed</span>
          </div>
          <div className="card-body">
            {(protocols || []).map((p, i) => (
              <div key={p.name} style={{ marginBottom: 12 }}>
                <div className="hstack" style={{ justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                  <span>{p.name}</span>
                  <span className="muted mono">{p.bytes} · {p.pct}%</span>
                </div>
                <div className="bar"><span style={{ width: `${Math.min(100, p.pct)}%`, background: i === 0 ? 'var(--ink-2)' : 'var(--ink-4)' }}/></div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>Recent traffic</h3>
          <span className="muted" style={{ fontSize: 11 }}>{top.length} events</span>
        </div>
        <div className="card-tight">
          <table className="tbl">
            <thead><tr>
              <th>Source</th><th>Destination</th><th>Proto</th><th>Bytes</th><th>Rule</th><th>Time</th><th style={{width:120}}>Status</th>
            </tr></thead>
            <tbody>
              {top.length === 0 && <tr><td colSpan="7" className="muted" style={{ textAlign: 'center', padding: 20 }}>Waiting for traffic…</td></tr>}
              {top.map((r, i) => (
                <tr key={i}>
                  <td className="mono">{(r.src || '').split(':')[0]}</td>
                  <td className="mono">{r.dst}</td>
                  <td><span className="chip">{r.proto}</span></td>
                  <td className="num muted">{r.bytes}</td>
                  <td><span className="chip">{r.rule}</span></td>
                  <td className="mono muted" style={{ fontSize: 11 }}>{(r.t || '').slice(0, 8)}</td>
                  <td>
                    {r.level === 'BLOCK'
                      ? <Badge tone="danger"><Dot tone="danger"/>Block</Badge>
                      : r.level === 'WARN'
                        ? <Badge tone="warn"><Dot tone="warn"/>Warn</Badge>
                        : <Badge tone="ok"><Dot tone="ok"/>Allow</Badge>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
};

const StatCard = ({ label, value, unit, delta, tone, live }) => (
  <div className="card kpi">
    <div className="label"><Dot tone="ok" live={live}/>{label}</div>
    <div className="value tabular">{value}{unit && <span className="unit">{unit}</span>}</div>
    <div className="meta">
      {delta ? <span className={`delta ${tone}`}>{tone === 'up' ? '↑' : tone === 'down' ? '↓' : '→'} {delta}</span> : null}
      <span>live</span>
    </div>
  </div>
);

// ====== Rules ======
const AllowlistPanel = () => {
  const [hosts, setHosts] = React.useState([]);
  const [input, setInput] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState('');

  const load = React.useCallback(async () => {
    const data = await window.FW.api.listAllowlist();
    setHosts(Array.isArray(data?.hosts) ? data.hosts : []);
  }, []);

  React.useEffect(() => { load(); }, [load]);

  const add = async (host) => {
    const v = (host || '').trim();
    if (!v) return;
    setBusy(true);
    setErr('');
    try {
      const res = await window.FW.api.addAllowlist(v);
      if (res && res.ok === false) setErr(res.error || 'Failed');
      setInput('');
      await load();
    } catch (e) {
      setErr(String(e));
    }
    setBusy(false);
  };

  const remove = async (host) => {
    if (!confirm(`Remove ${host} from allowlist? Traffic will be inspected again (likely blocked if cert-pinned).`)) return;
    await window.FW.api.deleteAllowlist(host);
    await load();
  };

  const PRESETS = [
    { label: 'WhatsApp', hosts: ['*.whatsapp.net', '*.whatsapp.com'] },
    { label: 'Snapchat', hosts: ['*.snapchat.com', '*.sc-cdn.net'] },
    { label: 'Signal',   hosts: ['*.signal.org'] },
    { label: 'Telegram', hosts: ['*.telegram.org', '*.t.me'] },
    { label: 'iMessage', hosts: ['*.apple.com', '*.icloud.com', '*.apple-cloudkit.com'] },
  ];

  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="card-head">
        <div>
          <h3>Allowlist — apps that bypass inspection</h3>
          <div className="sub">
            Cert-pinned apps (WhatsApp, Snapchat, etc.) cannot be MITM'd. Without allowlist entry they fail TLS and are logged as BLOCK. Listed hosts tunnel through untouched.
          </div>
        </div>
        <div className="hstack">
          <button className="btn btn-sm" onClick={load}><Icon name="refresh"/>Refresh</button>
        </div>
      </div>
      <div className="card-body">
        <form
          onSubmit={(e) => { e.preventDefault(); add(input); }}
          className="hstack"
          style={{ gap: 8, marginBottom: 12 }}
        >
          <input
            className="input"
            style={{ flex: 1 }}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Host or wildcard, e.g. *.whatsapp.net"
          />
          <button className="btn btn-primary" type="submit" disabled={busy}>
            <Icon name="plus"/>{busy ? 'Adding…' : 'Add'}
          </button>
        </form>

        <div className="hstack" style={{ flexWrap: 'wrap', gap: 6, marginBottom: 12 }}>
          <span className="muted" style={{ fontSize: 11, marginRight: 4 }}>Presets:</span>
          {PRESETS.map(p => (
            <button
              key={p.label}
              className="btn btn-ghost btn-sm"
              onClick={() => p.hosts.forEach(add)}
              disabled={busy}
              title={p.hosts.join(', ')}
            >
              <Icon name="plus"/>{p.label}
            </button>
          ))}
        </div>

        {err && <div style={{ color: 'var(--danger)', fontSize: 12, marginBottom: 8 }}>{err}</div>}

        {hosts.length === 0 ? (
          <div className="muted" style={{ fontSize: 12, padding: '8px 0' }}>
            No hosts allowlisted. Cert-pinned traffic is currently blocked by default.
          </div>
        ) : (
          <div className="hstack" style={{ flexWrap: 'wrap', gap: 6 }}>
            {hosts.map(h => (
              <span key={h} className="chip" style={{ gap: 6 }}>
                <span className="mono" style={{ fontSize: 11 }}>{h}</span>
                <button
                  className="btn btn-ghost btn-sm btn-icon"
                  style={{ padding: 2 }}
                  onClick={() => remove(h)}
                  title="Remove"
                >
                  <Icon name="close" size={12}/>
                </button>
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

const RulesPage = ({ rules, onToggle, onDelete, onAdd, onRefresh }) => {
  const [q, setQ] = React.useState('');
  const [cat, setCat] = React.useState('All');
  const [form, setForm] = React.useState({
    action: 'block',
    match_type: 'keyword',
    value: '',
    priority: 100,
    description: '',
  });
  const [formBusy, setFormBusy] = React.useState(false);
  const [formErr, setFormErr] = React.useState('');

  const cats = ['All', ...Array.from(new Set(rules.map(r => r.category)))];
  const filtered = rules.filter(r =>
    (cat === 'All' || r.category === cat) &&
    (r.name.toLowerCase().includes(q.toLowerCase()) || r.id.toLowerCase().includes(q.toLowerCase()))
  );

  const submit = async (e) => {
    e.preventDefault();
    setFormBusy(true);
    setFormErr('');
    try {
      const res = await onAdd(form);
      if (res && res.ok === false) {
        setFormErr(res.error || 'Failed');
      } else {
        setForm({ action: 'block', match_type: 'keyword', value: '', priority: 100, description: '' });
      }
    } catch (err) {
      setFormErr(String(err));
    }
    setFormBusy(false);
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Rules & Policies</h1>
          <div className="sub">{rules.filter(r => r.enabled).length} active of {rules.length} total</div>
        </div>
        <div className="toolbar">
          <button className="btn" onClick={onRefresh}><Icon name="refresh"/>Refresh</button>
        </div>
      </div>

      <AllowlistPanel/>

      {/* Inline rule creator (preserved from old dashboard) */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-head">
          <h3>New rule</h3>
          <span className="muted" style={{ fontSize: 11 }}>Evaluated before AI (first match wins, lowest priority first)</span>
        </div>
        <div className="card-body">
          <form onSubmit={submit} className="grid" style={{ gridTemplateColumns: 'repeat(6, 1fr)', gap: 12, alignItems: 'end' }}>
            <div className="field">
              <label>Action</label>
              <select className="select" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>
                <option value="block">Block</option>
                <option value="allow">Allow</option>
              </select>
            </div>
            <div className="field">
              <label>Match type</label>
              <select className="select" value={form.match_type} onChange={e => setForm({ ...form, match_type: e.target.value })}>
                <option value="ip_src">ip_src</option>
                <option value="ip_dst">ip_dst</option>
                <option value="port">port</option>
                <option value="domain">domain</option>
                <option value="keyword">keyword</option>
              </select>
            </div>
            <div className="field" style={{ gridColumn: 'span 2' }}>
              <label>Value</label>
              <input className="input" value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} required placeholder="e.g. badword, 22, example.com"/>
            </div>
            <div className="field">
              <label>Priority</label>
              <input className="input" type="number" value={form.priority} onChange={e => setForm({ ...form, priority: Number(e.target.value) })}/>
            </div>
            <div className="field" style={{ gridColumn: 'span 5' }}>
              <label>Description</label>
              <input className="input" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Optional"/>
            </div>
            <div className="field">
              <label>&nbsp;</label>
              <button className="btn btn-primary" type="submit" disabled={formBusy}>
                <Icon name="plus"/>{formBusy ? 'Saving…' : 'Add rule'}
              </button>
            </div>
            {formErr && <div style={{ gridColumn: 'span 6', color: 'var(--danger)', fontSize: 12 }}>{formErr}</div>}
          </form>
        </div>
      </div>

      <div className="card">
        <div className="card-head" style={{ flexWrap: 'wrap', gap: 10 }}>
          <div className="filters">
            {cats.map(c =>
              <button key={c} className="filter-pill" aria-pressed={c === cat} onClick={() => setCat(c)}>{c}</button>
            )}
          </div>
          <div className="search" style={{ maxWidth: 260, margin: 0 }}>
            <Icon name="search" className="s-ic"/>
            <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search rules…"/>
          </div>
        </div>
        <div className="card-tight">
          <table className="tbl">
            <thead><tr>
              <th style={{ width: 50 }}></th>
              <th style={{ width: 90 }}>ID</th>
              <th>Name</th>
              <th>Category</th>
              <th>Action</th>
              <th>Target</th>
              <th style={{ width: 100 }}>Hits / 24h</th>
              <th>Updated</th>
              <th style={{ width: 60 }}></th>
            </tr></thead>
            <tbody>
              {filtered.length === 0 && <tr><td colSpan="9" className="muted" style={{ textAlign: 'center', padding: 20 }}>No rules match.</td></tr>}
              {filtered.map(r => (
                <tr key={r.id}>
                  <td>
                    <button className="switch" aria-checked={r.enabled} onClick={() => onToggle(r.rawId)}/>
                  </td>
                  <td className="mono muted" style={{ fontSize: 11 }}>{r.id}</td>
                  <td>
                    <div style={{ fontWeight: 600 }}>{r.name}</div>
                    {!r.enabled && <div style={{ fontSize: 11, color: 'var(--ink-4)' }}>Disabled</div>}
                  </td>
                  <td><Badge tone="soft">{r.category}</Badge></td>
                  <td>
                    <Badge tone={r.action === 'Block' ? 'danger' : r.action === 'Allow' ? 'ok' : 'warn'}>
                      {r.action}
                    </Badge>
                  </td>
                  <td className="mono" style={{ fontSize: 12 }}>{r.targets}</td>
                  <td className="num tabular">{fmt.num(r.hits24h)}</td>
                  <td className="muted" style={{ fontSize: 12 }}>{r.updated}</td>
                  <td>
                    <button className="btn btn-ghost btn-sm btn-icon" onClick={() => onDelete(r.rawId)} title="Delete">
                      <Icon name="trash"/>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
};

// ====== Threats ======
const ThreatsPage = ({ threats, kpis, onRefresh }) => {
  const [sev, setSev] = React.useState('All');
  const levels = ['All', 'critical', 'high', 'medium', 'low'];
  const list = threats || [];
  const filtered = sev === 'All' ? list : list.filter(t => t.severity === sev);
  const criticals = list.filter(t => t.severity === 'critical').length;
  const highs = list.filter(t => t.severity === 'high').length;
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Threats</h1>
          <div className="sub">AI-classified events · <span className="mono">multi-service orchestrator</span></div>
        </div>
        <div className="toolbar">
          <button className="btn" onClick={onRefresh}><Icon name="refresh"/>Refresh</button>
        </div>
      </div>

      <div className="grid g-4" style={{ marginBottom: 16 }}>
        <StatCard label="Critical" value={String(criticals)} delta="" tone="up"/>
        <StatCard label="High" value={String(highs)} delta="" tone="up"/>
        <StatCard label="Blocked (total)" value={fmt.num(kpis?.blocked_24h || 0)} delta="" tone="up"/>
        <StatCard label="Classifier" value="multi" unit="" delta="" tone="flat"/>
      </div>

      <div className="card">
        <div className="card-head">
          <div className="filters">
            {levels.map(l =>
              <button key={l} className="filter-pill" aria-pressed={l === sev} onClick={() => setSev(l)}>{l}</button>
            )}
          </div>
          <div className="hstack">
            <button className="btn btn-sm" onClick={onRefresh}><Icon name="refresh"/></button>
          </div>
        </div>
        <div className="card-tight">
          <table className="tbl">
            <thead><tr>
              <th>ID</th><th>Time</th><th>Severity</th><th>Type</th>
              <th>Source</th><th>Target</th><th>Rule</th>
              <th style={{width:100}}>Confidence</th><th>Action</th>
            </tr></thead>
            <tbody>
              {filtered.length === 0 && <tr><td colSpan="9" className="muted" style={{ textAlign: 'center', padding: 20 }}>No threats in window.</td></tr>}
              {filtered.map(t => (
                <tr key={t.id}>
                  <td className="mono" style={{ fontSize: 11 }}>{t.id}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{t.time}</td>
                  <td><SevBadge level={t.severity}/></td>
                  <td><strong>{t.type}</strong></td>
                  <td><span className="mono">{t.src}</span> <span className="muted">({t.srcCountry})</span></td>
                  <td className="mono">{t.dst}</td>
                  <td><span className="chip">{t.rule}</span></td>
                  <td>
                    <div className="hstack">
                      <div className="bar" style={{ width: 52 }}><span style={{ width: `${t.confidence*100}%`, background: 'var(--ink-2)' }}/></div>
                      <span className="mono" style={{ fontSize: 11 }}>{Number(t.confidence).toFixed(2)}</span>
                    </div>
                  </td>
                  <td><Badge tone="danger">{t.action}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
};

// ====== Logs ======
const LogsPage = ({ logSamples, onRefresh }) => {
  const [filter, setFilter] = React.useState('All');
  const [q, setQ] = React.useState('');
  const lvls = ['All', 'BLOCK', 'WARN', 'ALLOW'];
  const rows = logSamples || [];
  const filtered = rows.filter(r =>
    (filter === 'All' || r.level === filter) &&
    (!q || (r.src + r.dst + r.msg + r.rule).toLowerCase().includes(q.toLowerCase()))
  );
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Logs</h1>
          <div className="sub">Live orchestrator event stream · {rows.length} entries stored</div>
        </div>

        <div className="toolbar">
          <button className="btn btn-sm" onClick={onRefresh}><Icon name="refresh"/>Refresh</button>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-head">
          <div className="filters">
            {lvls.map(l =>
              <button key={l} className="filter-pill" aria-pressed={l === filter} onClick={() => setFilter(l)}>{l}</button>
            )}
          </div>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11.5, padding: '10px 0', maxHeight: 800, minHeight: 400, overflowY: 'auto', border: '1px solid var(--border-subtle)', borderRadius: 4 }}>
          {filtered.length === 0 && <div className="muted" style={{ padding: 20, textAlign: 'center' }}>No log entries.</div>}
          {filtered.map((r, i) => (
            <div key={i} style={{
              display: 'grid',
              gridTemplateColumns: '110px 60px 170px 170px 60px 100px 70px 1fr',
              padding: '5px 16px',
              borderBottom: '1px solid var(--border)',
              alignItems: 'center', gap: 12,
            }}>
              <span style={{ color: 'var(--ink-4)' }}>{r.t}</span>
              <span style={{
                color: r.level === 'BLOCK' ? 'var(--danger)' : r.level === 'WARN' ? 'var(--warn)' : 'var(--ok)',
                fontWeight: 700
              }}>{r.level}</span>
              <span>{r.src}</span>
              <span>{r.dst}</span>
              <span style={{ color: 'var(--ink-3)' }}>{r.proto}</span>
              <span style={{ color: 'var(--ink-2)' }}>{r.rule}</span>
              <span style={{ color: 'var(--ink-3)' }}>{r.bytes}</span>
              <span className="ellip" style={{ color: 'var(--ink-2)' }}>{r.msg}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
};

// ====== Devices ======
const DevicesPage = ({ devices, onRefresh }) => (
  <>
    <div className="page-head">
      <div>
        <h1>Devices</h1>
        <div className="sub">{(devices || []).length} services probed</div>
      </div>
      <div className="toolbar">
        <button className="btn" onClick={onRefresh}><Icon name="refresh"/>Rediscover</button>
      </div>
    </div>

    <div className="grid g-3">
      {(devices || []).length === 0 && <div className="muted" style={{ padding: 20 }}>No devices reported.</div>}
      {(devices || []).map(d => (
        <div key={d.name} className="card">
          <div className="card-head">
            <div>
              <h3 className="mono">{d.name}</h3>
              <div className="sub">{d.role} · <span className="mono">{d.zone}</span></div>
            </div>
            <Badge tone={d.status === 'healthy' ? 'ok' : d.status === 'degraded' ? 'warn' : 'danger'}>
              <Dot tone={d.status === 'healthy' ? 'ok' : d.status === 'degraded' ? 'warn' : 'danger'}/>{d.status}
            </Badge>
          </div>
          <div className="card-body">
            <div className="vstack">
              <MetricRow label="CPU" value={`${d.cpu}%`} pct={d.cpu} tone={d.cpu > 75 ? 'warn' : 'ok'}/>
              <MetricRow label="Memory" value={`${d.mem}%`} pct={d.mem} tone={d.mem > 75 ? 'warn' : 'ok'}/>
            </div>
            <div className="hstack" style={{ marginTop: 14, justifyContent: 'space-between', fontSize: 12 }}>
              <span className="muted">Throughput</span>
              <span className="mono">{d.tput}</span>
            </div>
            <div className="hstack" style={{ marginTop: 6, justifyContent: 'space-between', fontSize: 12 }}>
              <span className="muted">Uptime</span>
              <span className="mono">{d.uptime}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  </>
);

const MetricRow = ({ label, value, pct, tone }) => (
  <div>
    <div className="hstack" style={{ justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
      <span className="muted">{label}</span>
      <span className="mono">{value}</span>
    </div>
    <div className={`bar ${tone}`}><span style={{ width: `${pct}%` }}/></div>
  </div>
);

// ====== Reports ======
const ReportsPage = ({ reports, onRefresh }) => (
  <>
    <div className="page-head">
      <div>
        <h1>Reports</h1>
        <div className="sub">On-demand reports from the orchestrator</div>
      </div>
      <div className="toolbar">
        <button className="btn" onClick={onRefresh}><Icon name="refresh"/>Refresh</button>
      </div>
    </div>

    <div className="card">
      <div className="card-tight">
        <table className="tbl">
          <thead><tr>
            <th>Name</th><th>Scope</th><th>Period</th><th>Size</th>
            <th style={{ width: 140 }}>Status</th><th style={{ width: 140 }}></th>
          </tr></thead>
          <tbody>
            {(reports || []).length === 0 && <tr><td colSpan="6" className="muted" style={{ textAlign: 'center', padding: 20 }}>No reports.</td></tr>}
            {(reports || []).map(r => (
              <tr key={r.name}>
                <td><strong>{r.name}</strong></td>
                <td>{r.scope}</td>
                <td className="muted">{r.period}</td>
                <td className="mono">{r.size}</td>
                <td>
                  <Badge tone={r.status === 'ready' ? 'ok' : r.status === 'generating' ? 'warn' : 'soft'}>
                    <Dot tone={r.status === 'ready' ? 'ok' : 'warn'} live={r.status === 'generating'}/>
                    {r.status}
                  </Badge>
                </td>
                <td>
                  <button className="btn btn-sm" disabled={r.status !== 'ready'}><Icon name="download"/>Download</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  </>
);

Object.assign(window, { TrafficPage, RulesPage, ThreatsPage, LogsPage, DevicesPage, ReportsPage, AllowlistPanel, StatCard, MetricRow });
