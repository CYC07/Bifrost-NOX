/* global React, Icon, Dot, Badge */

// ====== AI Intake (uploads) ======
const UploadsPage = ({ uploaded, onRefresh }) => {
  const [items, setItems] = React.useState(uploaded || []);
  const [drag, setDrag] = React.useState(false);
  const inputRef = React.useRef(null);

  React.useEffect(() => { setItems(uploaded || []); }, [uploaded]);

  const detectType = (f) => {
    if (f.type && f.type.startsWith('image')) return { kind: 'IMG', ct: 'image' };
    const ext = (f.name.split('.').pop() || '').toLowerCase();
    if (['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'].includes(ext)) return { kind: 'IMG', ct: 'image' };
    return { kind: (ext || 'DOC').toUpperCase().slice(0, 4), ct: 'document' };
  };

  const fmtSize = (n) => n > 1024 * 1024 ? `${(n / (1024 * 1024)).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`;

  const onFiles = async (files) => {
    const arr = Array.from(files);
    const pending = arr.map(f => ({
      name: f.name,
      size: fmtSize(f.size),
      type: detectType(f).kind,
      status: 'analyzing',
      time: 'just now',
      tags: ['Uploading…'],
    }));
    setItems(prev => [...pending, ...prev]);

    for (const f of arr) {
      const { ct } = detectType(f);
      try {
        const res = await window.FW.api.upload(f, ct);
        const status = (res && res.status || '').toLowerCase();
        setItems(prev => prev.map(p => p.name === f.name && p.status === 'analyzing'
          ? {
            ...p,
            status: status === 'block' ? 'flagged' : 'indexed',
            tags: [`risk=${res?.risk_level || 'unknown'}`, (res?.reason || '').slice(0, 60)],
          }
          : p));
      } catch (err) {
        setItems(prev => prev.map(p => p.name === f.name && p.status === 'analyzing'
          ? { ...p, status: 'flagged', tags: ['Upload failed'] }
          : p));
      }
    }

    // refresh backend-held queue
    if (onRefresh) onRefresh();
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>AI Intake</h1>
          <div className="sub">Upload images and documents for direct AI analysis via the orchestrator</div>
        </div>
        <div className="toolbar">
          <Badge tone="info"><Icon name="sparkles"/>CLIP + YOLO + OCR · YARA · Presidio</Badge>
        </div>
      </div>

      <div className="grid g-12-8" style={{ marginBottom: 16 }}>
        <div
          className={`dropzone ${drag ? 'dragover' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); onFiles(e.dataTransfer.files); }}
          onClick={() => inputRef.current?.click()}
        >
          <input ref={inputRef} type="file" multiple hidden onChange={(e) => onFiles(e.target.files)}/>
          <div style={{
            width: 40, height: 40, borderRadius: 10, background: 'var(--surface)',
            border: '1px solid var(--border)', display: 'grid', placeItems: 'center',
            margin: '0 auto 12px'
          }}>
            <Icon name="upload" size={18}/>
          </div>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Drop files to analyze</div>
          <div className="muted" style={{ fontSize: 13, marginBottom: 12 }}>
            PDF, DOCX, images · routed to the correct AI microservice
          </div>
          <button className="btn">Browse files</button>
          <div className="muted mono" style={{ fontSize: 11, marginTop: 12 }}>
            Analysis runs on-box (Image / Document / Text services)
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <h3>What the AI extracts</h3>
          </div>
          <div className="card-body">
            {[
              { icon: 'image', title: 'Image analysis', desc: 'NSFW (CLIP), object detection (YOLO), OCR (Tesseract)' },
              { icon: 'file', title: 'Document analysis', desc: 'YARA malware signatures, metadata, structure heuristics' },
              { icon: 'shield', title: 'PII & secrets', desc: 'Presidio patterns, API-key detection, SQLi heuristics' },
              { icon: 'zap', title: 'Static rule gate', desc: 'Hard-match IP / port / domain / keyword policy first' },
              { icon: 'sparkles', title: 'Verdict', desc: 'ALLOW / BLOCK / CENSOR with risk level and reason' },
            ].map(x => (
              <div key={x.title} className="hstack" style={{ gap: 12, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                <div style={{ width: 28, height: 28, borderRadius: 6, background: 'var(--bg-sunken)', display: 'grid', placeItems: 'center', flexShrink: 0, color: 'var(--ink-2)' }}>
                  <Icon name={x.icon} size={14}/>
                </div>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{x.title}</div>
                  <div className="muted" style={{ fontSize: 12 }}>{x.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <div>
            <h3>Intake queue</h3>
            <div className="sub">{items.length} items · {items.filter(i => i.status === 'indexed').length} indexed · {items.filter(i => i.status === 'flagged').length} flagged</div>
          </div>
          <div className="hstack">
            <button className="btn btn-sm" onClick={onRefresh}><Icon name="refresh"/>Refresh</button>
          </div>
        </div>
        <div className="card-tight">
          <table className="tbl">
            <thead><tr>
              <th style={{ width: 48 }}></th>
              <th>Name</th>
              <th style={{ width: 70 }}>Type</th>
              <th style={{ width: 90 }}>Size</th>
              <th>AI extraction</th>
              <th style={{ width: 120 }}>Status</th>
              <th style={{ width: 100 }}>Added</th>
            </tr></thead>
            <tbody>
              {items.length === 0 && <tr><td colSpan="7" className="muted" style={{ textAlign: 'center', padding: 20 }}>No uploads yet — drop files above.</td></tr>}
              {items.map((f, i) => (
                <tr key={f.name + f.time + i}>
                  <td>
                    <div style={{ width: 28, height: 28, borderRadius: 5, background: 'var(--bg-sunken)', display: 'grid', placeItems: 'center' }}>
                      <Icon name={f.type === 'IMG' ? 'image' : 'file'} size={14}/>
                    </div>
                  </td>
                  <td><strong>{f.name}</strong></td>
                  <td><span className="chip">{f.type}</span></td>
                  <td className="mono" style={{ fontSize: 12 }}>{f.size}</td>
                  <td>
                    <div className="hstack" style={{ flexWrap: 'wrap', gap: 4 }}>
                      {(f.tags || []).map((t, j) => <span key={j} className="chip" style={{ fontSize: 10 }}>{t}</span>)}
                    </div>
                  </td>
                  <td>
                    <Badge tone={f.status === 'indexed' ? 'ok' : f.status === 'analyzing' ? 'warn' : 'danger'}>
                      <Dot tone={f.status === 'indexed' ? 'ok' : f.status === 'analyzing' ? 'warn' : 'danger'} live={f.status === 'analyzing'}/>
                      {f.status}
                    </Badge>
                  </td>
                  <td className="muted" style={{ fontSize: 12 }}>{f.time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
};

Object.assign(window, { UploadsPage });
