"""
report.py  -  builds ONE self-contained HTML file (charts included) that can be opened in any browser,
e-mailed, or printed to PDF (Ctrl+P). It is the 'report you hand to your manager'.
"""
import base64
import datetime
import html
import io
import re

import matplotlib.pyplot as plt

from . import ui_charts
from .insights import cap_first, overall_status, unit_word

COLORS = ui_charts.RISK_COLOR


def _img(fig):
    if fig is None:
        return ""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130, facecolor=fig.get_facecolor())
    plt.close(fig)
    return '<img alt="chart" src="data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode() + '">'


def _md(text):
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", html.escape(text, quote=False))


def _badge(risk):
    fg = "#0b0b0b" if risk == "Medium" else "#fff"
    return f'<span class="badge" style="background:{COLORS[risk]};color:{fg}">{risk}</span>'


CSS = """
body{font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#0b0b0b;background:#f4f3ef;margin:0}
.page{max-width:900px;margin:0 auto;padding:32px 28px;background:#fff}
h1{margin:0 0 4px 0;font-size:28px} h2{margin:34px 0 10px 0;font-size:20px;border-bottom:2px solid #e1e0d9;padding-bottom:6px}
.sub{color:#52514e;margin:0 0 18px 0}
.status{padding:16px 18px;border-radius:10px;color:#fff;margin:14px 0}
.status b{font-size:20px}
.kpis{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}
.kpi{flex:1;min-width:150px;border:1px solid #e1e0d9;border-radius:10px;padding:12px 14px}
.kpi .v{font-size:24px;font-weight:700}.kpi .l{color:#52514e;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0}
th{background:#f4f3ef;text-align:left} th,td{padding:7px 9px;border-bottom:1px solid #e1e0d9;vertical-align:top}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:700}
img{max-width:100%;height:auto;margin:6px 0} .note{color:#52514e;font-size:13px}
.card{border:1px solid #e1e0d9;border-radius:10px;padding:12px 14px;margin:10px 0;page-break-inside:avoid}
ul{margin:6px 0 6px 18px;padding:0} li{margin:5px 0}
@media print{body{background:#fff}.page{padding:0}}
"""


def make_report_html(res, file_name="uploaded log", settings=None):
    lib, described, m = res["library"], res["described"], res.get("monthly")
    word = unit_word(lib.get("unit"))
    label, key, why = overall_status(described)
    rep = res["read_report"]
    now = datetime.datetime.now().strftime("%d %b %Y, %H:%M")
    p = []
    p.append(f"<h1>Security Log Pattern Report</h1><p class='sub'>{html.escape(file_name)} · created {now}</p>")
    p.append(f"<div class='status' style='background:{COLORS[key]};{'color:#0b0b0b' if key == 'Medium' else ''}'>"
             f"<b>{label}</b><br>{html.escape(why)}</div>")
    p.append(f"<p>{html.escape(res['summary'])}</p>")
    attn = [d for d in described if d["risk"] in ("High", "Medium")]
    kp = [("Log lines analysed", f"{rep['lines_read']:,}"), (cap_first(word), f"{lib['n_units']:,}"),
          ("Patterns found", len(described)), ("Need attention", len(attn))]
    p.append("<div class='kpis'>" + "".join(f"<div class='kpi'><div class='v'>{v}</div><div class='l'>{l}</div></div>" for l, v in kp) + "</div>")
    p.append(_img(ui_charts.risk_bar(described)))

    p.append("<h2>1. Patterns found</h2><p class='note'>Most important first. Risk labels come from simple rules; they are "
             "suggestions for an analyst, not proof of an attack.</p>")
    for d in described:
        ex = "".join(f"<li><code>{html.escape(e['sample_message'])}</code></li>" for e in d.get("examples", [])[:2])
        seen = f" · seen {d['first_seen'][:10]} to {d['last_seen'][:10]}" if d.get("first_seen") else ""
        p.append(f"<div class='card'>{_badge(d['risk'])} <b>{html.escape(d['label'])}</b> "
                 f"<span class='note'>({d['id']} · {d['share']*100:.1f}% of {word}{seen})</span>"
                 f"<p>{html.escape(d['meaning'])}<br><b>What to check:</b> {html.escape(d['check'])}</p>"
                 f"<ul>{ex}</ul></div>")
    p.append(_img(ui_charts.sizes_chart(described)))

    p.append("<h2>2. Monthly report</h2>")
    if m is None:
        p.append("<p>This log has no dates, so a month-by-month report is not possible.</p>")
    else:
        p.append("<ul>" + "".join(f"<li>{_md(f)}</li>" for f in m["findings"]) + "</ul>")
        p.append(_img(ui_charts.monthly_activity(m)))
        s = m["summary"]
        rows = "".join(
            f"<tr><td>{i}</td><td>{int(r.lines):,}</td><td>{int(r.groups):,}</td><td>{int(r.days_with_data)}</td>"
            f"<td>{r.high_share:.0f}%</td><td>{r.attention_share:.0f}%</td><td>{int(r.patterns_active)}</td></tr>"
            for i, r in s.iterrows())
        p.append(f"<table><tr><th>{m['unit_word'].capitalize()}</th><th>Log lines</th><th>Groups</th><th>Days with data</th>"
                 f"<th>High-risk share</th><th>High + Medium share</th><th>Patterns active</th></tr>{rows}</table>")
        p.append("<p class='note'>Which pattern was active in which month (share of that month's log lines):</p>")
        p.append(_img(ui_charts.monthly_heatmap(m, described)))

    p.append("<h2>3. Watch list</h2>")
    if len(res["watch"]):
        w = "".join(f"<tr><td>{html.escape(str(r['IP address']))}</td><td>{int(r['Log lines']):,}</td>"
                    f"<td>{html.escape(r['Main pattern'])}</td><td>{_badge(r['Risk'])}</td></tr>" for _, r in res["watch"].iterrows())
        p.append(f"<table><tr><th>IP address</th><th>Log lines</th><th>Main pattern</th><th>Risk</th></tr>{w}</table>")
    else:
        p.append("<p>This log has no IP addresses, so there is no IP watch list.</p>")

    p.append("<h2>4. How reliable is this?</h2><table><tr><th>Check</th><th>Result</th><th>Meaning</th></tr>"
             + "".join(f"<tr><td>{html.escape(r['name'])}</td><td>{r['value']} ({r['label']})</td><td>{html.escape(r['help'])}</td></tr>"
                       for r in res["reliability"]) + "</table>")
    p.append("<p class='note'>Patterns are groups of similar behaviour found automatically (K-Means / DBSCAN). "
             "Names, risk labels and MITRE ATT&amp;CK codes are rule-based hints, not proof.</p>")
    return ("<!doctype html><html><head><meta charset='utf-8'><title>Security Log Pattern Report</title>"
            f"<style>{CSS}</style></head><body><div class='page'>" + "\n".join(p) + "</div></body></html>").encode("utf-8")
