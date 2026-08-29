/**
 * Report Generation Module
 *
 * Builds downloadable HTML forensic reports from analysis results.
 */

import { humanizeCheckName, humanizeCategory, verdictColor } from './scoring.js';

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

export function buildReportHTML(report) {
  const prob = ((report.tamper_probability || 0) * 100).toFixed(1);
  const conf = ((report.confidence || 0) * 100).toFixed(1);
  const label = report.label || 'inconclusive';
  const color = verdictColor(label);

  const checksHTML = (report.checks || []).map(c => {
    const s = (Math.max(0, Math.min(1, c.score)) * 100).toFixed(1);
    const cn = (Math.max(0, Math.min(1, c.confidence)) * 100).toFixed(1);
    return `<div class="ck">
      <h3>${esc(humanizeCheckName(c.name))}</h3>
      <p class="sub">${esc(c.summary || '')}</p>
      <div class="br"><span>Anomaly</span><div class="bt"><div class="bf sc" style="width:${s}%"></div></div><b>${s}%</b></div>
      <div class="br"><span>Confidence</span><div class="bt"><div class="bf cf" style="width:${cn}%"></div></div><b>${cn}%</b></div>
    </div>`;
  }).join('');

  const segsHTML = (report.segments || []).slice(0, 40).map(seg =>
    `<li class="sg-item"><b>${esc(humanizeCategory(seg.category))}</b>: ${seg.start_s.toFixed(2)}s – ${seg.end_s.toFixed(2)}s (conf ${seg.confidence.toFixed(2)})</li>`
  ).join('');

  const explHTML = (report.explanation || []).map(l => `<li class="ex">${esc(l)}</li>`).join('');

  const dur = (report.duration_s || 0).toFixed(2);
  const sha = report.sha256 || '—';
  const mode = report.mode === 'client' ? 'Client-side (no server)'
    : report.mode === 'hybrid' ? 'Hybrid (client + server)'
    : report.mode === 'remote' ? 'Server (deep scan)'
    : report.mode || 'unknown';

  // Circumference for the gauge ring (r=52).
  const C = 2 * Math.PI * 52;
  const offset = (C * (1 - Math.max(0, Math.min(1, report.tamper_probability || 0)))).toFixed(1);

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>quevidkit Forensic Report</title>
<style>
:root{
  --bg:#eef1f5;--surface:#fff;--surface2:#f4f6fa;--inset:#f7f9fc;--border:#d6dde7;--border2:#e3e8ef;
  --ink:#101a26;--ink2:#38475a;--muted:#647689;--accent:#0c7c8c;--danger:#d63a4b;
  --display:'Space Grotesk',system-ui,sans-serif;--mono:'JetBrains Mono',ui-monospace,Menlo,monospace;
  --body:'Inter',system-ui,-apple-system,sans-serif;
}
@media(prefers-color-scheme:dark){:root{
  --bg:#0a0f16;--surface:#121a24;--surface2:#0f1620;--inset:#0b1119;--border:#26323f;--border2:#1d2732;
  --ink:#eaf1f7;--ink2:#b8c7d6;--muted:#8496a8;--accent:#2bc4d8;--danger:#ff5d6e;
}}
*{box-sizing:border-box}
body{font-family:var(--body);margin:0;padding:22px 16px;color:var(--ink);background:var(--bg);min-height:100vh}
.sh{max-width:900px;margin:0 auto}
h1,h2,h3,b{font-family:var(--display);color:var(--ink);letter-spacing:-.01em}
p,li{color:var(--ink2);line-height:1.55}ul{padding-left:0;list-style:none;margin:0;display:grid;gap:8px}
.cd{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:20px;margin-bottom:14px;box-shadow:0 2px 10px rgba(16,26,38,.06)}
.ey{font-family:var(--mono);text-transform:uppercase;letter-spacing:.14em;color:var(--accent);font-size:.7rem;margin:0 0 10px;font-weight:600}
.hd{display:flex;gap:20px;align-items:center;flex-wrap:wrap}
.gz{position:relative;width:120px;height:120px;flex:0 0 auto}
.gz svg{width:100%;height:100%;transform:rotate(-90deg)}
.gz .trk{fill:none;stroke:var(--inset);stroke-width:11}
.gz .fil{fill:none;stroke-width:11;stroke-linecap:round}
.gc{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gv{font-family:var(--display);font-size:1.7rem;font-weight:600;color:var(--ink)}
.gl{font-family:var(--mono);font-size:.55rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-top:2px}
.bg{display:inline-block;padding:8px 15px;border-radius:999px;color:#fff;font-family:var(--display);font-weight:700;letter-spacing:.06em}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:16px}
.sb{border:1px solid var(--border);border-radius:11px;padding:13px;background:var(--surface2)}
.sb p{margin:0;font-family:var(--mono);font-size:.66rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.sb h3{margin:6px 0 0;font-size:1.3rem}
.cg{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:10px}
.ck{border:1px solid var(--border);border-radius:12px;padding:14px;background:var(--surface2)}
.ck h3{margin:0 0 4px;font-size:1rem}
.sub{margin:0 0 10px;color:var(--muted);font-size:.86rem}
.br{display:grid;grid-template-columns:82px 1fr auto;gap:8px;align-items:center;font-size:.8rem;color:var(--muted);margin:6px 0}
.br b{font-family:var(--mono);color:var(--ink)}
.bt{height:8px;border-radius:999px;background:var(--inset);border:1px solid var(--border2);overflow:hidden}
.bf{height:100%}.sc{background:var(--danger)}.cf{background:var(--accent)}
li.ex{padding:11px 13px;background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:9px;white-space:pre-wrap;font-size:.86rem}
li.sg-item{font-family:var(--mono);font-size:.8rem;padding:8px 11px;background:var(--surface2);border:1px solid var(--border);border-radius:9px}
code{font-family:var(--mono)}
@media(max-width:600px){.sg,.cg{grid-template-columns:1fr}.br{grid-template-columns:1fr}}
</style></head><body>
<div class="sh">
<div class="cd"><p class="ey">quevidkit · forensic report</p>
<div class="hd">
<div class="gz"><svg viewBox="0 0 120 120"><circle class="trk" cx="60" cy="60" r="52"></circle>
<circle class="fil" cx="60" cy="60" r="52" stroke="${color}" stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${offset}"></circle></svg>
<div class="gc"><span class="gv">${Math.round(Number(prob))}%</span><span class="gl">Tamper prob.</span></div></div>
<div><span class="bg" style="background:${color}">${esc(label.toUpperCase())}</span>
<p style="margin:10px 0 0"><b>Mode:</b> ${esc(mode)}</p></div>
</div>
<div class="sg">
<div class="sb"><p>Tamper Probability</p><h3>${prob}%</h3></div>
<div class="sb"><p>Confidence</p><h3>${conf}%</h3></div>
<div class="sb"><p>Duration</p><h3>${dur}s</h3></div>
<div class="sb"><p>File</p><h3 style="font-size:.9rem;word-break:break-all">${esc(report.fileName || '—')}</h3></div>
</div>
<p style="margin-top:14px;font-size:.8rem;color:var(--muted)"><b>SHA-256:</b> <code>${esc(sha)}</code></p>
</div>
<div class="cd"><h2>Plain-Language Explanation</h2><ul>${explHTML || '<li class="ex">No explanation available.</li>'}</ul></div>
<div class="cd"><h2>Evidence Checks</h2><div class="cg">${checksHTML || '<p>No checks ran.</p>'}</div></div>
<div class="cd"><h2>Suspicious Segments</h2><ul>${segsHTML || '<li class="sg-item">None detected.</li>'}</ul></div>
<div class="cd" style="font-size:.76rem;color:var(--muted)"><p>Generated by quevidkit v1.0.0 on ${new Date().toISOString()}</p></div>
</div></body></html>`;
}

export function downloadReport(report) {
  const html = buildReportHTML(report);
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `quevidkit_report_${Date.now()}.html`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
