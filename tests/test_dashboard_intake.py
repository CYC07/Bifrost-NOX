"""Dashboard AI-Intake logic (dashboard/data.js): upload() must not call an HTTP error a success.

Bug (seen live): the page read `res.status` from the response body only, so a 403 `{"error": ...}` became "indexed,
risk=unknown" and the row then vanished when the page re-read the server's queue. data.js now reports
{ok, httpStatus, error|verdict}, and FW.intake holds the pure row/merge/tone helpers the page uses.
The tests run data.js in node's `vm` with a fake window/fetch (skipped when node is not installed).
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_JS = os.path.join(ROOT, "dashboard", "data.js")
NODE = shutil.which("node")

HARNESS = r"""
const vm = require('vm'), fs = require('fs');
const code = fs.readFileSync(process.argv[2], 'utf8');
function load(fetchImpl) {
  const window = {};
  const ctx = { window, fetch: fetchImpl, console, Promise, setTimeout, FormData: class { constructor() { this.items = []; } append(k, v) { this.items.push([k, v]); } } };
  vm.createContext(ctx); vm.runInContext(code, ctx);
  return { FW: window.FW, fd: ctx.FormData };
}
const res = (status, body, jsonFails) => ({ ok: status >= 200 && status < 300, status, json: async () => { if (jsonFails) throw new Error('not json'); return body; } });
const out = [];
const t = async (name, fn) => { try { const r = await fn(); out.push({ name, ok: r === true, got: r === true ? undefined : r }); } catch (e) { out.push({ name, ok: false, got: String(e) }); } };
const FILE = { name: 'pic.png', size: 100 };
const VERDICT = { status: 'allow', risk_level: 'safe', reason: 'ok', detailed_findings: { findings: ['Classified as: x (0.1)'], scores: { semantic: 0.1 } } };

(async () => {
  await t('upload ok returns the verdict', async () => { const { FW } = load(async () => res(200, VERDICT)); const r = await FW.api.upload(FILE, 'image'); return r.ok === true && r.httpStatus === 200 && r.verdict.status === 'allow' || r; });
  await t('upload 403 is a failure that keeps the server message', async () => { const { FW } = load(async () => res(403, { error: 'forbidden: admin action requires a loopback client' })); const r = await FW.api.upload(FILE, 'image'); return r.ok === false && r.httpStatus === 403 && r.error.includes('forbidden') || r; });
  await t('upload 500 with a non-JSON body is a failure', async () => { const { FW } = load(async () => res(500, null, true)); const r = await FW.api.upload(FILE, 'image'); return r.ok === false && r.httpStatus === 500 && r.error.includes('500') || r; });
  await t('upload network error is a failure', async () => { const { FW } = load(async () => { throw new TypeError('Failed to fetch'); }); const r = await FW.api.upload(FILE, 'image'); return r.ok === false && r.httpStatus === 0 && r.error.includes('Could not reach') || r; });
  await t('upload 200 with an empty or non-object body is a failure', async () => { for (const b of [null, 'x', 5]) { const { FW } = load(async () => res(200, b)); const r = await FW.api.upload(FILE, 'image'); if (r.ok !== false) return r; } return true; });
  await t('upload posts the file as multipart with the intake fields', async () => { let seen; const { FW } = load(async (url, opts) => { seen = { url, opts }; return res(200, VERDICT); }); await FW.api.upload(FILE, 'image'); const keys = seen.opts.body.items.map(x => x[0]); return seen.url === '/analyze_traffic' && seen.opts.method === 'POST' && ['content_type', 'source_ip', 'destination_ip', 'file'].every(k => keys.includes(k)) || seen; });

  const { FW } = load(async () => res(200, VERDICT)); const I = FW.intake;
  await t('failure message for 403 tells the operator what to do', () => { const m = I.failureMessage({ ok: false, httpStatus: 403, error: 'forbidden: admin action requires a loopback client' }); return /localhost/i.test(m) && /403/.test(m) || m; });
  await t('failure message for other errors names the status and the server text', () => { const m = I.failureMessage({ ok: false, httpStatus: 502, error: 'bad gateway' }); return m.includes('502') && m.includes('bad gateway') || m; });
  await t('failure message for a network error is the error itself', () => I.failureMessage({ ok: false, httpStatus: 0, error: 'Could not reach the firewall: x' }).includes('Could not reach') || true);
  await t('pendingRow is local and pending', () => { const r = I.pendingRow({ name: 'a.png', size: '1 KB', type: 'IMG' }); return r.local === true && r.state === 'pending' && r.status === 'analyzing' && r.name === 'a.png' || r; });
  await t('failedRow is a visible error row with the reason', () => { const r = I.failedRow({ name: 'a.png', size: '1 KB', type: 'IMG' }, { ok: false, httpStatus: 403, error: 'forbidden' }); return r.status === 'error' && r.local && r.state === 'failed' && r.tags.length >= 1 && /403/.test(r.tags.join(' ')) || r; });
  await t('merge keeps pending and failed local rows ahead of the server rows and drops done ones', () => {
    const local = [{ name: 'p', local: true, state: 'pending' }, { name: 'f', local: true, state: 'failed' }, { name: 'd', local: true, state: 'done' }];
    const backend = [{ name: 's1' }, { name: 's2' }];
    const m = I.merge(local, backend);
    return JSON.stringify(m.map(r => r.name)) === JSON.stringify(['p', 'f', 's1', 's2']) || m; });
  await t('merge tolerates null/undefined and does not mutate its inputs', () => { const l = [{ name: 'p', local: true, state: 'pending' }]; const b = [{ name: 's' }]; const before = JSON.stringify([l, b]); I.merge(l, b); return JSON.stringify([l, b]) === before && I.merge(null, undefined).length === 0 && I.merge(undefined, b).length === 1; });
  await t('tone maps every status', () => ['indexed:ok', 'review:warn', 'analyzing:warn', 'flagged:danger', 'error:danger', 'failed:danger', 'weird:warn'].every(p => { const [s, tn] = p.split(':'); return I.tone(s) === tn; }));
  await t('counts includes review and error', () => { const c = I.counts([{ status: 'indexed' }, { status: 'indexed' }, { status: 'review' }, { status: 'flagged' }, { status: 'error' }, { status: 'analyzing' }]); return c.indexed === 2 && c.review === 1 && c.flagged === 1 && c.error === 1 && c.analyzing === 1 && c.total === 6 || c; });
  await t('detailLines lists reason, findings, scores and error', () => {
    const lines = I.detailLines({ detail: { reason: 'r', risk: 'safe', findings: ['f1', 'f2'], scores: { semantic: 0.13 }, error: '' } });
    const j = lines.join('\n'); return j.includes('r') && j.includes('f1') && j.includes('f2') && j.includes('semantic') && j.includes('0.13') || lines; });
  await t('detailLines shows the error and handles rows without detail', () => { const e = I.detailLines({ detail: { findings: [], scores: {}, error: 'image service HTTP 500' } }).join(' '); return e.includes('image service HTTP 500') && I.detailLines({}).length === 0 && I.detailLines(null).length === 0 || e; });
  console.log(JSON.stringify(out));
})();
"""


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_dashboard_intake_logic(tmp_path):
    h = tmp_path / "harness.js"
    h.write_text(HARNESS)
    p = subprocess.run([NODE, str(h), DATA_JS], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr[-800:]
    results = json.loads(p.stdout.strip().splitlines()[-1])
    bad = [r for r in results if not r["ok"]]
    assert len(results) >= 17, f"harness ran only {len(results)} cases"
    assert not bad, json.dumps(bad, indent=1)[:1500]
