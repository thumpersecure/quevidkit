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
    `<li><b>${esc(humanizeCategory(seg.category))}</b>: ${seg.start_s.toFixed(2)}s – ${seg.end_s.toFixed(2)}s (conf ${seg.confidence.toFixed(2)})</li>`
  ).join('');

  const explHTML = (report.explanation || []).map(l => `<li>${esc(l)}</li>`).join('');

  const dur = (report.duration_s || 0).toFixed(2);
  const sha = report.sha256 || '—';
  const mode = report.mode === 'client' ? 'Client-side (no server)'
    : report.mode === 'hybrid' ? 'Hybrid (client + server)'
    : report.mode === 'remote' ? 'Server (deep scan)'
    : report.mode || 'unknown';

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>quevidkit Forensic Report</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:20px;color:#edf4ff;
  background:radial-gradient(circle at top,#18253e 0%,#08111f 62%,#050914 100%);min-height:100vh}
.sh{max-width:960px;margin:0 auto}
.cd{background:rgba(16,24,39,.94);border:1px solid #2d3c5a;border-radius:14px;padding:18px;margin-bottom:14px;box-shadow:0 16px 40px rgba(0,0,0,.28)}
.ey{text-transform:uppercase;letter-spacing:.18em;color:#8bd4ff;font-size:.72rem;margin:0 0 8px}
.bg{display:inline-block;padding:7px 14px;border-radius:999px;color:#06111c;font-weight:700;letter-spacing:.08em}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-top:12px}
.sb{border:1px solid #2d3c5a;border-radius:12px;padding:12px;background:rgba(8,17,31,.78)}
.sb p{margin:0;font-size:.82rem;color:#9db0cb;text-transform:uppercase;letter-spacing:.06em}
.sb h3{margin:4px 0 0;font-size:1.2rem}
.mt{height:14px;border-radius:999px;background:#0a1527;border:1px solid #263653;overflow:hidden;margin-top:10px}
.mf{height:14px;background:linear-gradient(90deg,#3dd68c 0%,#f6b73c 55%,#ff5a6b 100%)}
.cg{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}
.ck{border:1px solid #2d3c5a;border-radius:12px;padding:12px;background:rgba(8,17,31,.78)}
.ck h3{margin:0 0 4px}
.sub{margin:0 0 8px;color:#9db0cb;font-size:.88rem}
.br{display:grid;grid-template-columns:90px 1fr auto;gap:6px;align-items:center;font-size:.84rem;color:#c4d3ea;margin:4px 0}
.bt{height:10px;border-radius:999px;background:#0a1527;border:1px solid #22314d;overflow:hidden}
.bf{height:10px}.sc{background:#ff5a6b}.cf{background:#5aa9ff}
.tl{position:relative;height:30px;border-radius:12px;background:linear-gradient(90deg,rgba(90,169,255,.08),rgba(90,169,255,.02)),rgba(7,14,24,.86);border:1px solid #2d3c5a}
.tb{position:absolute;top:3px;height:24px;background:linear-gradient(90deg,rgba(246,183,60,.88),rgba(255,90,107,.94));border-radius:8px;opacity:.85}
h1,h2,h3,b{color:#edf4ff}p,li{color:#c4d3ea;line-height:1.55}ul{padding-left:18px}
@media(max-width:600px){.sg,.cg{grid-template-columns:1fr}.br{grid-template-columns:1fr}}
</style></head><body>
<div class="sh">
<div class="cd"><p class="ey">quevidkit · forensic report</p>
<h1>Investigation Summary</h1>
<p><b>Mode:</b> ${esc(mode)}</p>
<span class="bg" style="background:${color}">${esc(label.toUpperCase())}</span>
<div class="sg">
<div class="sb"><p>Tamper Probability</p><h3>${prob}%</h3></div>
<div class="sb"><p>Confidence</p><h3>${conf}%</h3></div>
<div class="sb"><p>Duration</p><h3>${dur}s</h3></div>
<div class="sb"><p>File</p><h3 style="font-size:.9rem;word-break:break-all">${esc(report.fileName || '—')}</h3></div>
</div>
<div class="mt"><div class="mf" style="width:${prob}%"></div></div>
<p style="margin-top:10px;font-size:.82rem;color:#9db0cb"><b>SHA-256:</b> <code>${esc(sha)}</code></p>
</div>
<div class="cd"><h2>Plain-Language Explanation</h2><ul>${explHTML || '<li>No explanation available.</li>'}</ul></div>
<div class="cd"><h2>Evidence Checks</h2><div class="cg">${checksHTML || '<p>No checks ran.</p>'}</div></div>
<div class="cd"><h2>Suspicious Segments</h2><ul>${segsHTML || '<li>None detected.</li>'}</ul></div>
<div class="cd" style="font-size:.78rem;color:#6f7d97"><p>Generated by quevidkit on ${new Date().toISOString()}</p></div>
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
