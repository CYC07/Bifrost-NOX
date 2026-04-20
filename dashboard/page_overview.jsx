/* global React, Icon, Sparkline, Dot, Badge, SevBadge, fmt */

// ====== Overview ======
const OverviewPage = ({ series, threats, countries, kpis, logSamples, liveTick }) => {
  const [events, setEvents] = React.useState(() => (logSamples || []).slice(0, 8));

  React.useEffect(() => {
    setEvents((logSamples || []).slice(0, 8));
  }, [logSamples]);

  React.useEffect(() => {
    const id = setInterval(async () => {
      await window.FW.api.refreshLogs();
      setEvents((window.FW.logSamples || []).slice(0, 8));
    }, 3500);
    return () => clearInterval(id);
  }, []);

  const safeSeries = series || { throughput: [], blocked: [], sessions: [], latency: [] };

  const kpiCards = [
    {
      label: 'Throughput (events/interval)',
      value: (kpis?.throughput ?? 0).toFixed ? kpis.throughput.toFixed(2) : (kpis?.throughput || 0),
      unit: '',
      delta: '+' + (liveTick || 0),
      tone: 'up',
      series: safeSeries.throughput,
    },
    {
      label: 'Threats Blocked',
      value: fmt.num(kpis?.blocked_24h || 0),
      unit: '',
      delta: '+' + (safeSeries.blocked?.[safeSeries.blocked.length - 1] || 0),
      tone: 'up',
      series: safeSeries.blocked,
      accent: 'danger',
    },
    {
      label: 'Active Sessions',
      value: fmt.num(kpis?.active_sessions || 0),
      unit: '',
      delta: '+1.8%',
      tone: 'up',
      series: safeSeries.sessions,
    },
    {
      label: 'p95 Latency',
      value: (kpis?.p95_latency || 0).toString(),
      unit: 'ms',
      delta: '—',
      tone: 'flat',
      series: safeSeries.latency,
    },
  ];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <div className="sub">
            Real-time posture · <span className="mono">AI Firewall FYP</span>
          </div>
        </div>
        <div className="toolbar">
          <div className="filters">
            {['1h', '24h', '7d', '30d'].map(t =>
              <button key={t} className="filter-pill" aria-pressed={t === '24h'}>{t}</button>
            )}
          </div>
          <button className="btn" onClick={() => window.FW.api.refreshAll()}>
            <Icon name="refresh"/>Refresh
          </button>
        </div>
      </div>

      <div className="grid g-4" style={{ marginBottom: 16 }}>
        {kpiCards.map((k, i) => (
          <div key={i} className="card kpi">
            <div className="label">
              <Dot tone={k.accent || 'ok'} live={i === 0}/>
              {k.label}
            </div>
            <div className="value tabular">
              {k.value}{k.unit && <span className="unit">{k.unit}</span>}
            </div>
            <div className="meta">
              <span className={`delta ${k.tone}`}>
                {k.tone === 'up' ? '↑' : k.tone === 'down' ? '↓' : '→'} {k.delta}
              </span>
              <span>vs prev interval</span>
            </div>
            <div style={{ marginTop: 14, marginLeft: -4, marginRight: -4 }}>
              <Sparkline data={k.series} color={k.accent === 'danger' ? 'var(--danger)' : 'var(--ink-2)'} height={36}/>
            </div>
          </div>
        ))}
      </div>

      <div className="grid g-12-8" style={{ marginBottom: 16 }}>
        <div className="card">
          <div className="card-head">
            <div>
              <h3>Threat activity</h3>
              <div className="sub">Blocked events over time, grouped by category</div>
            </div>
            <div className="filters">
              <button className="filter-pill" aria-pressed="true">All</button>
              <button className="filter-pill">WAF</button>
              <button className="filter-pill">DLP</button>
              <button className="filter-pill">AI</button>
            </div>
          </div>
          <div className="card-body">
            <ThreatChart data={safeSeries.blocked}/>
            <div className="hstack" style={{ marginTop: 14, flexWrap: 'wrap', gap: 16 }}>
              <Legend color="var(--danger)" label="Blocks" val={fmt.num(kpis?.blocked_24h || 0)}/>
              <Legend color="var(--warn)" label="Warns" val={countEvents(events, 'WARN')}/>
              <Legend color="var(--ok)" label="Allows" val={fmt.num(kpis?.active_sessions || 0)}/>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <div className="hstack">
              <Dot tone="ok" live/>
              <h3>Live events</h3>
            </div>
            <span className="muted" style={{ fontSize: 11 }}>Streaming</span>
          </div>
          <div className="feed" style={{ maxHeight: 420, overflow: 'hidden' }}>
            {events.length === 0 && (
              <div className="feed-item muted" style={{ gridTemplateColumns: '1fr' }}>
                No events yet — waiting for proxy traffic.
              </div>
            )}
            {events.map((e, i) => (
              <div key={(e.t || '') + i} className="feed-item">
                <Dot tone={e.level === 'BLOCK' ? 'danger' : e.level === 'WARN' ? 'warn' : 'ok'}/>
                <span className="t">{(e.t || '').slice(0, 12)}</span>
                <div className="msg ellip">
                  <span className="act">{e.level}</span>{' '}
                  <span className="src">{(e.src || '').split(':')[0]} → {e.dst}</span>
                </div>
                <span className="chip">{e.rule}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid g-8-4">
        <div className="card">
          <div className="card-head">
            <div>
              <h3>Recent threats</h3>
              <div className="sub">AI-classified events</div>
            </div>
            <div className="hstack">
              <button className="btn btn-sm"><Icon name="filter"/>Filter</button>
            </div>
          </div>
          <div className="card-tight">
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 70 }}>Sev</th>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Target</th>
                  <th>Rule</th>
                  <th style={{ width: 90 }}>Confidence</th>
                  <th style={{ width: 90 }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {(threats || []).length === 0 && (
                  <tr><td colSpan="7" className="muted" style={{ textAlign: 'center', padding: 20 }}>
                    No threats detected yet.
                  </td></tr>
                )}
                {(threats || []).slice(0, 6).map(t => (
                  <tr key={t.id}>
                    <td><SevBadge level={t.severity}/></td>
                    <td><strong>{t.type}</strong><div className="muted mono" style={{ fontSize: 11 }}>{t.id} · {t.time}</div></td>
                    <td><span className="mono">{t.src}</span> <span className="muted">({t.srcCountry})</span></td>
                    <td className="mono">{t.dst}</td>
                    <td><span className="chip">{t.rule}</span></td>
                    <td>
                      <div className="hstack">
                        <div className="bar" style={{ width: 52 }}><span style={{ width: `${t.confidence * 100}%`, background: 'var(--ink-2)' }}/></div>
                        <span className="mono" style={{ fontSize: 11 }}>{Number(t.confidence).toFixed(2)}</span>
                      </div>
                    </td>
                    <td><Badge tone={t.action === 'Blocked' ? 'danger' : 'soft'}>{t.action}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="vstack" style={{ gap: 16 }}>
          <div className="card">
            <div className="card-head">
              <h3>Top source countries</h3>
              <span className="muted" style={{ fontSize: 11 }}>24h</span>
            </div>
            <div className="card-body" style={{ padding: '10px 18px 14px' }}>
              {(countries || []).length === 0 && (
                <div className="muted" style={{ fontSize: 12, padding: '8px 0' }}>No data yet.</div>
              )}
              {(countries || []).slice(0, 6).map(c => (
                <div key={c.code} className="geo-row">
                  <span className="flag">{c.code}</span>
                  <span>
                    <div>{c.name}</div>
                    <div className="bar" style={{ marginTop: 4 }}>
                      <span style={{
                        width: `${Math.min(100, c.pct * 2.5)}%`,
                        background: c.kind === 'block' ? 'var(--danger)' : c.kind === 'mixed' ? 'var(--warn)' : 'var(--ink-3)'
                      }}/>
                    </div>
                  </span>
                  <span className="mono tabular muted" style={{ fontSize: 11 }}>{c.pct}%</span>
                  <span className="mono tabular" style={{ fontSize: 11 }}>{fmt.compact(c.hits)}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-head">
              <h3>Test controls</h3>
              <span className="muted" style={{ fontSize: 11 }}>/test_attack</span>
            </div>
            <div className="card-body">
              <div className="hstack" style={{ flexWrap: 'wrap', gap: 6 }}>
                <button className="btn btn-sm" onClick={() => window.FW.api.triggerTest('safe').then(window.FW.api.refreshOverview)}>
                  <Icon name="check"/>Safe
                </button>
                <button className="btn btn-sm" onClick={() => window.FW.api.triggerTest('malware').then(window.FW.api.refreshOverview)}>
                  <Icon name="alert"/>Malware
                </button>
                <button className="btn btn-sm" onClick={() => window.FW.api.triggerTest('sql').then(window.FW.api.refreshOverview)}>
                  <Icon name="zap"/>SQLi
                </button>
              </div>
              <div className="muted" style={{ fontSize: 11, marginTop: 10 }}>
                Injects synthetic events into the pipeline for testing rules & detection.
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

const countEvents = (events, level) => fmt.num((events || []).filter(e => e.level === level).length);

const ThreatChart = ({ data }) => {
  const src = (data && data.length ? data : new Array(32).fill(0));
  const bars = Math.min(32, src.length);
  const slice = src.slice(-bars);
  const max = Math.max(...slice, 1);
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', height: 200, gap: 4 }}>
      {slice.map((v, i) => {
        const h = (v / max) * 100;
        return (
          <div key={i} style={{ flex: 1, height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'flex-end' }}>
            <div style={{ height: `${h}%`, background: 'var(--danger)', borderRadius: 3, minHeight: v > 0 ? 3 : 0 }}/>
          </div>
        );
      })}
    </div>
  );
};

const Legend = ({ color, label, val }) => (
  <div className="hstack" style={{ fontSize: 12 }}>
    <span style={{ width: 10, height: 10, background: color, borderRadius: 2 }}/>
    <span className="muted">{label}</span>
    <span className="mono">{val}</span>
  </div>
);

Object.assign(window, { OverviewPage, ThreatChart, Legend });
