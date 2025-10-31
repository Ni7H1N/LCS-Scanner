# scanner/report_generator.py — LCS-Scanner v5 (Futuristic CyberOps Edition)
# ---------------------------------------------------------------------------
# Features:
#  - Responsive glassmorphic UI (cyber dashboard style)
#  - Chart.js + GSAP animations
#  - Interactive filtering, search, and export (PDF / JSON / CSV)
#  - Auto-open report in browser
#  - UTF-8 safe and color consistent with dark cyber theme
# ---------------------------------------------------------------------------

from jinja2 import Template
from collections import Counter
import datetime, html, json, os, webbrowser

HTML_TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>⚡ LCS-Scanner v5 — Futuristic Security Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/gsap.min.js"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700&family=Inter:wght@400;600&display=swap');
    :root {
      --bg: #010818;
      --card: rgba(10,20,45,0.7);
      --accent: #00f2ff;
      --accent2: #8b5cf6;
      --text: #e2e8f0;
      --meta: #94a3b8;
      --border: #1e293b;
      --glow: 0 0 15px rgba(0, 242, 255, 0.4);
    }
    body {
      background: radial-gradient(circle at top left, #030b1b, #000);
      color: var(--text);
      font-family: 'Inter', sans-serif;
      margin: 0;
      padding: 30px;
      overflow-x: hidden;
    }
    h1 {
      font-family: 'Orbitron', sans-serif;
      font-size: 2.3em;
      color: var(--accent);
      text-shadow: 0 0 25px rgba(0,242,255,0.6);
      text-align: center;
      margin-bottom: 10px;
      letter-spacing: 0.5px;
    }
    .meta { color: var(--meta); font-size: 14px; text-align:center; margin-bottom:20px; }
    .card {
      background: var(--card);
      border: 1px solid rgba(255,255,255,0.08);
      box-shadow: 0 0 25px rgba(0,255,255,0.08);
      padding: 20px;
      border-radius: 14px;
      margin: 20px auto;
      width: 92%;
      max-width: 1100px;
      backdrop-filter: blur(14px);
    }
    .issue {
      border: 1px solid rgba(255,255,255,0.05);
      padding: 12px;
      border-radius: 10px;
      margin-top: 10px;
      background: rgba(8,12,25,0.85);
      transition: all 0.3s ease;
      box-shadow: 0 0 10px rgba(0,0,0,0.2);
    }
    .issue:hover {
      transform: translateY(-2px);
      box-shadow: 0 0 20px rgba(0,255,255,0.25);
    }
    .badge {
      padding: 4px 9px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: bold;
      color: #fff;
    }
    .sev-High { background: #ef4444; }
    .sev-Medium { background: #f59e0b; }
    .sev-Low { background: #22c55e; }
    .sev-Critical { background: #b91c1c; }
    .sev-Info { background: #3b82f6; }
    .search {
      width: 30%;
      padding: 8px;
      margin: 5px;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: rgba(15,25,45,0.85);
      color: var(--text);
    }
    button {
      background: linear-gradient(90deg,var(--accent),var(--accent2));
      border: none;
      padding: 9px 13px;
      border-radius: 8px;
      font-weight: 600;
      color: #000;
      cursor: pointer;
      transition: 0.3s;
      margin: 3px;
    }
    button:hover {
      background: #00ffff;
      box-shadow: var(--glow);
      transform: scale(1.05);
    }
    .footer { color: var(--meta); font-size: 13px; text-align:center; margin-top:30px; }
  </style>
</head>
<body>
  <h1>⚡ LCS-Scanner — Futuristic CyberOps Report</h1>
  <div class="meta">Generated: {{ generated }}</div>

  <div class="card" id="summary">
    <canvas id="sevChart" height="100"></canvas>
    <p style="text-align:center;margin-top:12px;">
      Total Findings: <b>{{ issue_count }}</b> • Files: <b>{{ file_count }}</b> • Top Tags: {{ top_tags }}
    </p>
    <div style="text-align:center;">
      <button onclick="window.print()">🖨️ PDF</button>
      <button onclick="exportJSON()">💾 JSON</button>
      <button onclick="exportCSV()">📊 CSV</button>
    </div>
  </div>

  <div class="card">
    <input id="searchBox" class="search" placeholder="🔍 Search findings...">
    <select id="sevFilter" class="search">
      <option value="">Filter by severity</option>
      <option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option>
    </select>
    <div id="issues">
      {% for f in findings %}
      <div class="issue" data-sev="{{f.severity}}" data-title="{{f.title|lower}}">
        <h3>{{ f.title }}</h3>
        <div class="meta">{{f.file}} • <span class="badge sev-{{f.severity}}">{{f.severity}}</span> • Confidence: {{f.confidence}}</div>
        <div><b>Explain:</b> {{ f.explain }}</div>
        {% if f.ai_context %}<div><b>AI Context:</b> {{ f.ai_context }}</div>{% endif %}
        {% if f.fix %}<div><b>Fix:</b> {{ f.fix }}</div>{% endif %}
        {% if f.compliance %}<div><b>Compliance:</b> {{ f.compliance }}</div>{% endif %}
      </div>
      {% endfor %}
    </div>
  </div>

  <div class="footer">LCS-Scanner v5 — Interactive Cyber Report • Generated {{ generated }}</div>

<script>
const findings = {{ findings_json|safe }};
const ctx = document.getElementById('sevChart');
const sevCounts = {Critical:0,High:0,Medium:0,Low:0,Info:0};
findings.forEach(f=>{ sevCounts[f.severity]=(sevCounts[f.severity]||0)+1; });
new Chart(ctx,{type:'doughnut',data:{labels:Object.keys(sevCounts),datasets:[{data:Object.values(sevCounts),backgroundColor:['#b91c1c','#ef4444','#f59e0b','#22c55e','#3b82f6'],borderColor:'rgba(255,255,255,0.08)',borderWidth:2}]},options:{plugins:{legend:{position:'bottom',labels:{color:'#a3bffa'}}}}});

// Filters
function filter(){
  const q=document.getElementById('searchBox').value.toLowerCase();
  const sev=document.getElementById('sevFilter').value;
  document.querySelectorAll('.issue').forEach(el=>{
    const matchTitle=el.dataset.title.includes(q);
    const matchSev=!sev||el.dataset.sev===sev;
    el.style.display=(matchTitle&&matchSev)?'block':'none';
  });
}
document.getElementById('searchBox').addEventListener('input',filter);
document.getElementById('sevFilter').addEventListener('change',filter);

// Export JSON / CSV
function exportJSON(){
  const blob=new Blob([JSON.stringify(findings,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='lcs_report.json';a.click();
}
function exportCSV(){
  const rows=[["title","file","severity","score","confidence","fix"]];
  findings.forEach(f=>rows.push([f.title,f.file,f.severity,f.score,f.confidence,f.fix||'']));
  const csv=rows.map(r=>r.join(',')).join('\\n');
  const blob=new Blob([csv],{type:'text/csv'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='lcs_report.csv';a.click();
}

// GSAP Animation
gsap.from("h1",{duration:1.2,y:-50,opacity:0,ease:"power3.out"});
gsap.from(".card",{duration:1,y:40,opacity:0,stagger:0.2,ease:"power2.out"});
gsap.from(".issue",{duration:0.6,opacity:0,stagger:0.05,delay:0.8});
</script>
</body>
</html>
"""

def generate_full_html(findings, out_path):
    """Generate professional futuristic report."""
    generated = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    file_counts = Counter([f.get('file','unknown') for f in findings]).most_common(10)
    file_count = len(set(f.get('file') for f in findings))
    issue_count = len(findings)
    top_tags = ", ".join(sorted({t for f in findings for t in f.get('tags', [])}))

    safe_findings=[]
    for f in findings:
        sf={k:(html.escape(str(v)) if isinstance(v,str) else v) for k,v in f.items()}
        safe_findings.append(sf)

    tpl = Template(HTML_TEMPLATE)
    out_html = tpl.render(
        generated=generated,
        findings=safe_findings,
        findings_json=json.dumps(findings),
        issue_count=issue_count,
        file_count=file_count,
        top_tags=top_tags
    )

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(out_html)

    print(f"[+] HTML report generated at: {out_path}")
    try:
        webbrowser.open(f"file://{os.path.abspath(out_path)}")
    except Exception as e:
        print(f"[!] Could not auto-open: {e}")

if __name__ == "__main__":
    sample = [
        {"title":"Public S3 Bucket","file":"samples/main.tf","severity":"High","score":8.0,"confidence":"High","explain":"Bucket allows public ACLs","fix":"Restrict ACLs","tags":["aws","s3"],"ai_context":"Exposure of cloud storage","compliance":{"CIS":["CIS 13.6"],"NIST":["AC-4"]}},
        {"title":"Plaintext Password","file":"samples/Dockerfile","severity":"High","score":7.5,"confidence":"High","explain":"Hardcoded password","fix":"Use vault","tags":["code","secrets"],"ai_context":"Hardcoded secret risk","compliance":{"ISO27001":["A.9.4.3"],"GDPR":["Art. 25"]}}
    ]
    generate_full_html(sample, "./reports/test_futuristic.html")
