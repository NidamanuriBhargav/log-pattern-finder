"""
Security Log Pattern Finder - the web page.

One page, three sections:
    1. Upload your log
    2. Check the settings
    3. Your insights

Run it with:   streamlit run app.py
"""
import html
import io
import json
import os
import re

import pandas as pd
import streamlit as st

from logpattern import detect, ui_charts
from logpattern.insights import GLOSSARY, cap_first, overall_status, unit_word
from logpattern.monthly import export_monthly_csv
from logpattern.report import make_report_html
from logpattern.service import (DEFAULT_MAX_LINES, UserError, analyse, export_units_csv)

HERE = os.path.dirname(os.path.abspath(__file__))
HOST_MAX_LINES = int(os.environ.get("LOGPATTERN_MAX_LINES", 700_000))   # most lines one analysis may read (lower it on small free servers)
SAMPLES = {
    "SSH login log": ("sample_ssh.log", "ssh"),
    "Apache web-server log": ("sample_apache.log", "apache"),
    "Firewall log": ("sample_firewall.csv", "firewall"),
}
RISK_COLOR = ui_charts.RISK_COLOR
RISK_TEXT = {"High": "#ffffff", "Medium": "#0b0b0b", "Low": "#ffffff", "Normal": "#ffffff"}
RISK_HELP = {
    "High": "Looks like an attack technique - check first.",
    "Medium": "Mostly failed or blocked activity - worth a look.",
    "Low": "Probably fine, but good to confirm.",
    "Normal": "Looks like everyday activity.",
}
COLUMN_HELP = {
    "timestamp": "The column with the date and time of each event. Needed for the timeline and for time windows.",
    "src_ip": "The column with the IP address of whoever caused the event (the visitor or attacker).",
    "action": "The column that says if the event worked or failed (for example allow / deny, success / failed).",
    "dst_port": "The column with the port or service that was used (for example 22 or 443).",
    "message": "The column with the text of the event. Used to name and describe the patterns.",
    "user": "The column with the user name, if there is one.",
    "bytes_out": "The column with how much data was sent out. Helps spot large uploads.",
    "bytes_in": "The column with how much data was received.",
    "session_id": "The column that identifies one session or connection, if there is one.",
}
UNIT_DESCRIPTION = {
    "session": "We study each login session separately: all lines belonging to one login attempt are one group.",
    "client": "We study each visitor separately: all lines coming from the same IP address are one group.",
    "ip_window": "We study each IP address separately for each time window (you set the length below).",
    "row": "We study each line of the file as its own group (every line is already one connection).",
}
ADJ = {"month": "monthly", "week": "weekly", "day": "daily"}
CSV_QUESTIONS = [
    ("timestamp", "Which column has the date and time?"),
    ("src_ip", "Which column has the IP address of who did it?"),
    ("action", "Which column says if it worked or failed (the result)?"),
    ("dst_port", "Which column has the port or service that was used?"),
    ("message", "Which column has the message or description?"),
    ("user", "Which column has the user name?"),
    ("bytes_out", "Which column has the amount of data sent?"),
    ("bytes_in", "Which column has the amount of data received?"),
    ("session_id", "Which column identifies a session or connection?"),
]

st.set_page_config(page_title="Security Log Pattern Finder", page_icon="🛡️", layout="centered")

# ------------------------------------------------------------------ look and feel
# Colours are semi-transparent greys and "inherit", so the page reads well in light AND dark mode.
st.markdown("""
<style>
.block-container {max-width: 940px; padding-top: 2rem;}
.hero {padding:1.3rem 1.6rem; border-radius:16px; margin-bottom:.4rem;
       background:linear-gradient(135deg, rgba(42,120,214,.18), rgba(98,80,214,.10));}
.hero h1 {margin-bottom:.2rem;}
.hero p {font-size:1.05rem; opacity:.85; margin:0;}
.steps {display:flex; gap:.5rem; margin:1rem 0 1.5rem 0; flex-wrap:wrap;}
.step {flex:1; min-width:150px; padding:.6rem .9rem; border-radius:10px; border:1px solid rgba(128,128,128,.35);
       opacity:.55; font-weight:600;}
.step.active {opacity:1; border-color:#2a78d6; background:rgba(42,120,214,.12);}
.step.done {opacity:1; border-color:#1baf7a; background:rgba(27,175,122,.12);}
.step span {display:inline-block; width:1.5rem; height:1.5rem; line-height:1.5rem; text-align:center;
            border-radius:50%; background:rgba(128,128,128,.3); margin-right:.5rem; font-size:.85rem;}
.step.active span {background:#2a78d6; color:#fff;}
.step.done span {background:#1baf7a; color:#fff;}
.locked {padding:1rem 1.2rem; border:1px dashed rgba(128,128,128,.45); border-radius:10px; opacity:.65;}
.badge {display:inline-block; padding:.12rem .6rem; border-radius:999px; font-size:.78rem; font-weight:700;}
.muted {opacity:.7; font-size:.9rem;}
.banner {padding:1.1rem 1.3rem; border-radius:12px; background:rgba(128,128,128,.10); border-left:6px solid #2a78d6;
         margin:.4rem 0 1rem 0; font-size:1.02rem; line-height:1.5;}
.banner-tag {font-size:.72rem; font-weight:800; letter-spacing:.08em;}
.banner-title {font-size:1.7rem; font-weight:800; margin:.1rem 0 .4rem 0;}
.kpis {display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:.75rem; margin:.2rem 0 1.2rem 0;}
.kpi {border:1px solid rgba(128,128,128,.3); border-radius:12px; padding:.8rem 1rem; background:rgba(128,128,128,.06);}
.kpi-v {font-size:1.75rem; font-weight:800; line-height:1.15;}
.kpi-l {font-size:.85rem; opacity:.7;}
.pcard {border:1px solid rgba(128,128,128,.3); border-left:6px solid #2a78d6; border-radius:12px;
        padding:.9rem 1.1rem; margin:.7rem 0 .3rem 0; background:rgba(128,128,128,.05);}
.card-title {font-size:1.1rem; font-weight:700; margin:.15rem 0;}
.bar {height:8px; border-radius:4px; background:rgba(128,128,128,.22); margin:.35rem 0 .6rem 0;}
.bar > div {height:8px; border-radius:4px;}
.check {margin-top:.5rem; padding:.45rem .7rem; border-radius:8px; background:rgba(42,120,214,.10); font-size:.93rem;}
.findings {padding:1rem 1.2rem; border-radius:12px; background:rgba(42,120,214,.08); line-height:1.7; margin:.5rem 0 1rem 0;}
.rel {display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 1rem; margin:.5rem 0;
      border:1px solid rgba(128,128,128,.3); border-radius:12px;}
.rel-v {font-size:1.3rem; font-weight:800; white-space:nowrap;}
.stTabs [data-baseweb="tab"] {font-weight:600; padding:.6rem 1rem;}
.stTabs [data-baseweb="tab-list"] {gap:.25rem; flex-wrap:wrap;}
</style>
""", unsafe_allow_html=True)

# ------------------------------------------------------------------ state
ss = st.session_state
for key, default in dict(file_bytes=None, file_name=None, source=None, detected=None, step=1,
                         result=None, report_html=None, uploader_key=0, upload_id=None, scroll=False,
                         settings_used=None).items():
    ss.setdefault(key, default)


def reset_all():
    ss.update(file_bytes=None, file_name=None, source=None, detected=None, step=1, result=None, report_html=None,
              upload_id=None, scroll=False, settings_used=None)
    ss.uploader_key += 1
    for k in [k for k in ss if k.startswith("set_")]:
        del ss[k]


def load_file(name, data, source):
    """Remember a new file and look at it. Everything after it starts again."""
    for k in [k for k in ss if k.startswith("set_")]:
        del ss[k]
    ss.update(file_bytes=data, file_name=name, source=source, step=1, result=None, scroll=False)
    key, note, cols = detect.detect_log_type(detect.head_text(io.BytesIO(data)))
    ss.detected = dict(key=key, note=note, cols=cols,
                       preview=[l[:160] for l in data[:20000].decode("utf-8", "ignore").splitlines()[:5]],
                       n_lines=data.count(b"\n") + 1)


def badge(text, risk):
    return (f'<span class="badge" style="background:{RISK_COLOR[risk]};color:{RISK_TEXT[risk]}">{text}</span>')


def esc(text):
    return html.escape(str(text), quote=False)


def md_bold(text):
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", esc(text))


def pattern_card_html(d, word, compact=False):
    """One pattern as a clean card: risk badge, title, size bar, what it means, what to check."""
    extra = "" if compact else f' · {d["size"]:,} {word}'
    seen = ""
    if not compact and d.get("first_seen"):
        seen = f' · seen {d["first_seen"][:10]} → {d["last_seen"][:10]}'
    c = RISK_COLOR[d["risk"]]
    return (f'<div class="pcard" style="border-left-color:{c}">'
            f'{badge(d["risk"] + " risk", d["risk"])} <span class="muted">{d["id"]} · {d["share"]*100:.1f}% of {word}{extra}{seen}</span>'
            f'<div class="card-title">{esc(d["label"])}</div>'
            f'<div class="bar"><div style="width:{max(d["share"]*100, 1.5):.1f}%;background:{c}"></div></div>'
            f'<div>{esc(d["meaning"])}</div>'
            f'<div class="check"><b>What to check:</b> {esc(d["check"])}</div></div>')


# ------------------------------------------------------------------ header + step bar
st.markdown('<div class="hero"><h1>🛡️ Security Log Pattern Finder</h1>'
            '<p>Upload a security log. We group months of events into a few clear patterns of behaviour '
            'and tell you in plain words which ones deserve your attention.</p></div>', unsafe_allow_html=True)


def step_bar():
    current = 3 if ss.result else ss.step
    labels = ["Upload your log", "Check the settings", "See your insights"]
    html = '<div class="steps">'
    for i, lab in enumerate(labels, start=1):
        done = i < current or (i == 3 and ss.result)
        cls = "done" if done else ("active" if i == current else "")
        mark = "✓" if done else str(i)
        html += f'<div class="step {cls}"><span>{mark}</span>{lab}</div>'
    st.markdown(html + "</div>", unsafe_allow_html=True)


step_bar()

# ================================================================== SECTION 1 - upload
st.header("1 · Upload your log")
st.caption("Works with SSH logs, Apache error logs, firewall logs and any CSV file with a header row. "
           "Your file is analysed in memory and is never saved.")

uploaded = st.file_uploader("Drag a log file here, or click to browse", type=["log", "txt", "csv"],
                            key=f"uploader_{ss.uploader_key}",
                            help="Allowed file types: .log, .txt, .csv. Maximum file size: 1 GB.")
st.caption("📁 Allowed: .log, .txt or .csv files up to **1 GB**. "
           "(File size is different from the number of lines we analyse - you choose that in step 2.)")
if uploaded is not None and ss.upload_id != uploaded.file_id:
    ss.upload_id = uploaded.file_id
    load_file(uploaded.name, uploaded.getvalue(), "upload")
    st.rerun()

st.markdown("**No log at hand? Try a sample:**")
cols = st.columns(len(SAMPLES))
for col, (label, (fname, _)) in zip(cols, SAMPLES.items()):
    if col.button(label, use_container_width=True, key=f"sample_{fname}"):
        with open(os.path.join(HERE, "samples", fname), "rb") as f:
            load_file(fname, f.read(), "sample")
        st.rerun()

det = ss.detected
if ss.file_bytes is not None and det:
    size_mb = len(ss.file_bytes) / 1_000_000
    with st.container(border=True):
        st.markdown(f"**📄 {ss.file_name}** &nbsp; · &nbsp; {size_mb:.1f} MB &nbsp; · &nbsp; about {det['n_lines']:,} lines"
                    + (" &nbsp; · &nbsp; sample file" if ss.source == "sample" else ""))
        if det["key"] in ("ssh", "apache", "firewall"):
            st.success(f"Looks good - we think this is an **{detect.LOG_TYPES[det['key']]}**. {det['note']}")
        elif det["key"] == "csv":
            st.info(f"This is a general CSV table. {det['note']} In the next step you tell us which column is which.")
        else:
            st.error(f"{det['note']} Please upload a text log (.log / .txt) from SSH or Apache, "
                     "or a CSV file with a header row.")
        st.caption("First lines of your file:")
        st.code("\n".join(det["preview"]) or "(empty)", language=None)
    if det["key"] != "unknown" and ss.step == 1 and not ss.result:
        if st.button("Continue to settings  →", type="primary", key="go_settings"):
            ss.step = 2
            st.rerun()

# ================================================================== SECTION 2 - settings
st.header("2 · Check the settings")
if ss.step < 2 and not ss.result:
    st.markdown('<div class="locked">🔒 This step opens after you upload a file. '
                'Everything here is pre-filled, so you can usually just press the button.</div>',
                unsafe_allow_html=True)
else:
    st.caption("We filled in the best choices for you. Change something only if you know you need to.")
    with st.container(border=True):
        # ---- log type
        type_keys = list(detect.LOG_TYPES)
        default_type = det["key"] if det["key"] in type_keys else "csv"
        log_type = st.selectbox("What kind of log is this?", type_keys, index=type_keys.index(default_type),
                                format_func=lambda k: detect.LOG_TYPES[k], key="set_log_type",
                                help="We detected this automatically from the content of your file.")
        st.caption("We guessed this by reading your file. Change it only if the guess is wrong. "
                   "**SSH** = login records, **Apache** = web-server errors, **Firewall** = allowed/blocked connections, "
                   "**Other CSV** = any table - you will match the columns.")
        if log_type != det["key"] and det["key"] in type_keys:
            st.warning("This is different from what we detected. If the results look strange, switch back.")

        # ---- column matching (other CSV files only)
        columns, fail_values = {}, []
        if log_type == "csv":
            st.markdown("**Match your columns** - answer what you can; leave the rest as *(none)*.")
            try:
                head = pd.read_csv(io.BytesIO(ss.file_bytes), nrows=5000)
            except Exception:
                head = None
                st.error("We could not read this file as a CSV table. Pick another log type above.")
            if head is not None:
                guesses = detect.guess_columns(list(head.columns), head)
                options = ["(none)"] + list(head.columns)
                for field, question in CSV_QUESTIONS:
                    g = guesses.get(field)
                    choice = st.selectbox(question, options, index=options.index(g) if g in options else 0,
                                          key=f"set_col_{field}", help=COLUMN_HELP[field])
                    st.caption(COLUMN_HELP[field])
                    if choice != "(none)":
                        columns[field] = choice
                if "action" in columns:
                    values = head[columns["action"]].dropna().astype(str).unique().tolist()[:40]
                    bad = [v for v in values if any(w in v.lower() for w in
                                                    ("deny", "denied", "fail", "drop", "block", "reject", "error", "refus"))]
                    fail_values = st.multiselect("Which of these results mean something went wrong?", values,
                                                 default=bad, key="set_fail_values",
                                                 help="Pick the results that mean denied, blocked or failed.")
                    st.caption("Pick every result that means denied, blocked or failed. We pre-ticked the obvious ones. "
                               "This tells us which events were 'bad'.")
        # ---- what to group
        opts = detect.unit_options(log_type, columns)
        unit = st.radio("What should we group together?", list(opts), format_func=lambda k: opts[k], key=f"set_unit_{log_type}",
                        help="We study groups, not single lines. A group can be one login session, one visitor (IP address), "
                             "or one connection. The recommended choice is already selected.")
        st.caption(UNIT_DESCRIPTION.get(unit, ""))
        window = 10
        if unit == "ip_window":
            window = st.number_input("Length of the time window (minutes)", 1, 240, 10, key="set_window",
                                     help="Events from the same IP address within this many minutes count as one group.")
            st.caption("Example: 10 means all events from one IP address inside the same 10 minutes are one group. "
                       "Shorter = more, smaller groups. Longer = fewer, bigger groups.")

        # ---- how much data
        total = max(int(det["n_lines"]), 1)
        cap = min(total, HOST_MAX_LINES)
        if cap <= 5000:
            max_lines = cap
            st.markdown(f"**How many lines should we analyse?** All {cap:,} lines of your file (it is small).")
        else:
            max_lines = st.slider("How many lines should we analyse?", 5000, cap, min(cap, DEFAULT_MAX_LINES),
                                  step=5000, key="set_max_lines",
                                  help="Not the file size! This is how many lines, counted from the top of the file, we study. "
                                       "Fewer lines = faster. More lines = more complete.")
            st.caption("Your file can be up to 1 GB - that is its *size*. This slider is different: it says how many "
                       "*lines from the top* we study. Fewer lines is faster; more lines gives a fuller picture. "
                       "If you are unsure, keep the default.")
        if total > cap:
            st.info(f"Your file has about {total:,} lines. This server analyses at most {cap:,} of them (from the top).")
        est = int(10 + max_lines / 3000)
        st.caption(f"⏱ Estimated time: about {est} seconds" if est < 90 else f"⏱ Estimated time: about {est/60:.1f} minutes")

        # ---- privacy
        anonymize = st.toggle("Hide IP addresses in the results", value=False, key="set_anon",
                              help="Replaces every IP address by a short code (for example ip-3fa9c1b2), "
                                   "so you can share the results safely. The same IP always gets the same code.")
        st.caption("**Off (default):** results show the real IP addresses, e.g. 183.62.140.253. "
                   "**On:** every IP address becomes a code like ip-3fa9c1b2 in all tables, examples and downloads. "
                   "Turn it **on** when you will show or share the results with other people. "
                   "It does not change the patterns, only what you see.")

        # ---- advanced
        n_patterns = None
        with st.expander("Advanced (optional)"):
            mode = st.radio("How many patterns?", ["Automatic (recommended)", "I will choose"], key="set_k_mode",
                            help="Automatic tries 3 to 10 patterns and keeps the clearest result.")
            st.caption("**Automatic** tries different numbers of patterns and keeps the one that is clearest - "
                       "best for most people. Choose a number yourself only if you want fewer, simpler groups (3) "
                       "or more detail (10).")
            if mode == "I will choose":
                n_patterns = st.slider("Number of patterns", 3, 10, 5, key="set_k")

    # ---- plain-language summary + button
    unit_txt = unit_word(unit, plural=True)
    st.markdown(f"**What will happen:** we will read the first **{max_lines:,} lines** of *{ss.file_name}* as an "
                f"**{detect.LOG_TYPES[log_type]}**, group them into **{unit_txt}**, and find the patterns "
                f"{'automatically' if not n_patterns else f'(exactly {n_patterns})'}. "
                f"IP addresses will be **{'hidden' if anonymize else 'shown'}**.")
    ready = not (log_type == "csv" and (not columns or (unit in ('client', 'ip_window') and 'src_ip' not in columns)))
    if not ready:
        st.warning("Please match at least one column" + (" - and the IP address column to group by IP address." if log_type == "csv" else "."))

    if st.button("🔍 Find patterns", type="primary", disabled=not ready, key="run"):
        settings = dict(log_type=log_type, unit=unit, window_minutes=window, max_lines=max_lines,
                        anonymize=anonymize, n_patterns=n_patterns, columns=columns, fail_values=fail_values)
        STEPS = {1: "Reading your file", 2: "Grouping events", 3: "Finding patterns", 4: "Writing insights"}
        bar = st.progress(0.0, text="Starting ...")
        finished = False

        def progress(i, text):
            bar.progress(i / 4, text=f"Step {i} of 4 - {STEPS[i]} ...")

        try:
            ss.result = analyse(io.BytesIO(ss.file_bytes), settings, progress)
            ss.settings_used = settings
            try:
                ss.report_html = make_report_html(ss.result, ss.file_name)
            except Exception:                    # the report is a bonus - never block the page for it
                ss.report_html = None
            ss.scroll = True
            bar.progress(1.0, text="Done!")
            finished = True
        except UserError as e:
            bar.empty()
            st.error(f"**We could not finish.** {e}")
        except MemoryError:
            bar.empty()
            st.error("**The file is too big for this server.** Lower the number of lines in the settings and try again.")
        except Exception as e:                       # never show a raw traceback to the user
            bar.empty()
            st.error("**Something unexpected went wrong.** Try fewer lines, or a different log type. "
                     f"(Technical detail: {type(e).__name__}: {e})")
        if finished:
            st.rerun()

# ================================================================== SECTION 3 - insights
st.markdown('<div id="insights"></div>', unsafe_allow_html=True)
st.header("3 · Your insights")
res = ss.result
if res is None:
    st.markdown('<div class="locked">🔒 Your results will appear here after you press <b>Find patterns</b>.</div>',
                unsafe_allow_html=True)
else:
    if ss.scroll:
        import streamlit.components.v1 as components
        components.html("<script>const e=window.parent.document.getElementById('insights');"
                        "if(e){e.scrollIntoView({behavior:'smooth'});}</script>", height=0)
        ss.scroll = False

    lib, described, monthly = res["library"], res["described"], res.get("monthly")
    word = unit_word(lib.get("unit"))
    attn = [d for d in described if d["risk"] in ("High", "Medium")]
    status_label, status_key, status_why = overall_status(described)
    colour = RISK_COLOR[status_key]

    # ---- headline banner + 4 key numbers (always visible)
    st.markdown(
        f'<div class="banner" style="border-left-color:{colour}">'
        f'<div class="banner-tag" style="color:{colour}">OVERALL RESULT</div>'
        f'<div class="banner-title">{status_label}</div>'
        f'<div>{esc(res["summary"])}</div></div>', unsafe_allow_html=True)
    kpis = [("Log lines analysed", f"{res['read_report']['lines_read']:,}"),
            (cap_first(word) + " analysed", f"{lib['n_units']:,}"),
            ("Patterns found", f"{len(described)}"),
            ("Need attention", f"{len(attn)}")]
    st.markdown('<div class="kpis">' + "".join(
        f'<div class="kpi"><div class="kpi-v">{v}</div><div class="kpi-l">{l}</div></div>' for l, v in kpis) + "</div>",
        unsafe_allow_html=True)

    tab_over, tab_pat, tab_month, tab_watch, tab_rel = st.tabs(
        ["📊 Overview", "🧩 Patterns", "📅 Monthly report", "👁 Watch list", "✅ How reliable?"])

    # ================= Overview
    with tab_over:
        st.subheader("How risky is your log?")
        st.caption("All groups split by risk level. Red and amber are the parts worth your time.")
        st.pyplot(ui_charts.risk_bar(described), clear_figure=True)
        st.markdown(f"<div class='muted'>{esc(status_why)}</div>", unsafe_allow_html=True)

        st.subheader("Start here: the top things to check")
        top = [d for d in described if d["risk"] in ("High", "Medium")][:3] or described[:3]
        for d in top:
            st.markdown(pattern_card_html(d, word, compact=True), unsafe_allow_html=True)
        st.caption("The **Patterns** tab lists every pattern with examples.")

        if res["has_time"]:
            fig = ui_charts.activity_chart(res["units"], described)
            if fig is not None:
                st.subheader("When did it happen?")
                st.caption("Each bar is the number of groups that started in that period, coloured by risk. "
                           "Tall red bars mean a burst of risky activity.")
                st.pyplot(fig, clear_figure=True)

    # ================= Patterns
    with tab_pat:
        st.subheader("Every pattern we found")
        st.caption("A pattern is a group of similar behaviour. Risk labels are suggestions from simple rules - "
                   "they are **not proof** of an attack.")
        present = [r for r in ("High", "Medium", "Low", "Normal") if any(d["risk"] == r for d in described)]
        pick = st.radio("Show", ["All"] + present, horizontal=True, key="risk_filter",
                        help="Filter the list by risk level.")
        shown = [d for d in described if pick == "All" or d["risk"] == pick]
        for d in shown:
            st.markdown(pattern_card_html(d, word), unsafe_allow_html=True)
            with st.expander(f"Details of {d['id']}"):
                if d.get("examples"):
                    st.markdown("**Typical examples from your log**")
                    for ex in d["examples"]:
                        st.code(ex["sample_message"], language=None)
                left, right = st.columns(2)
                if d.get("top_sources"):
                    left.markdown("**Most active IP addresses**")
                    for s_ in d["top_sources"]:
                        left.markdown(f"- `{s_['src_ip']}` - {s_['events']:,} lines")
                if d.get("top_targets"):
                    right.markdown("**Most common targets**")
                    for s_ in d["top_targets"]:
                        right.markdown(f"- `{s_['target']}` - {s_['events']:,} lines")
                if d.get("first_seen"):
                    st.markdown(f"**When:** {d['first_seen'][:10]} to {d['last_seen'][:10]} "
                                f"({d['active_days']} active day(s)).")
                if d.get("mitre"):
                    st.caption("MITRE ATT&CK hints (not proof): " + ", ".join(d["mitre"]))
        st.subheader("Pattern sizes side by side")
        st.caption("Longer bar = more of your groups behave this way.")
        st.pyplot(ui_charts.sizes_chart(described), clear_figure=True)
        with st.expander("For specialists: what makes each pattern different?"):
            st.caption("Red = higher than average, blue = lower than average (numbers are standard deviations).")
            st.pyplot(ui_charts.difference_heatmap(described, res["features"]), clear_figure=True)
            st.caption(f"Method: {res['model']['algorithm'].upper()} clustering · features: {', '.join(res['features'])} · "
                       f"finished in {res['seconds']} s")

    # ================= Monthly report
    with tab_month:
        if monthly is None:
            st.markdown('<div class="locked">📅 A monthly report needs dates. This log has no timestamps '
                        '(the firewall CSV only lists connections), so we cannot split it by month.</div>',
                        unsafe_allow_html=True)
        else:
            nper, uw = monthly["n_periods"], monthly["unit_word"]
            st.subheader(f"{uw.capitalize()}-by-{uw} report")
            st.caption(f"Data from **{monthly['start']:%d %b %Y}** to **{monthly['end']:%d %b %Y}** "
                       f"({monthly['span_days']} days, {nper} {uw}{'s' if nper != 1 else ''}).")
            st.markdown('<div class="findings">' + "".join(f"<div>• {md_bold(f)}</div>" for f in monthly["findings"])
                        + "</div>", unsafe_allow_html=True)

            st.subheader("Activity each " + uw)
            st.caption("Bar height = log lines. Colours = risk level. The text above a bar shows the total and the "
                       "share that fell in High-risk patterns.")
            st.pyplot(ui_charts.monthly_activity(monthly), clear_figure=True)

            st.subheader("Numbers per " + uw)
            sm = monthly["summary"].copy()
            table = pd.DataFrame({
                uw.capitalize(): sm.index,
                "Log lines": sm["lines"].astype(int).values,
                "Groups": sm["groups"].astype(int).values,
                "Days with data": sm["days_with_data"].astype(int).values,
                "High-risk %": sm["high_share"].round(0).values,
                "High + Medium %": sm["attention_share"].round(0).values,
                "Patterns active": sm["patterns_active"].astype(int).values,
                "Biggest pattern": sm["top_pattern"].values,
            })
            if sm["unique_ips"].sum() > 0:
                table.insert(3, "Unique IPs", sm["unique_ips"].astype(int).values)
            st.dataframe(table, hide_index=True, use_container_width=True, column_config={
                "High-risk %": st.column_config.ProgressColumn("High-risk %", format="%d%%", min_value=0, max_value=100),
                "High + Medium %": st.column_config.ProgressColumn("High + Medium %", format="%d%%", min_value=0, max_value=100)})
            st.caption("**Days with data** shows how many days of the " + uw + " the log actually covers - a low number "
                       "means the totals for that " + uw + " are understated.")

            st.subheader("Which pattern was active when?")
            st.caption("Each cell = share of that " + uw + "'s log lines in that pattern. Darker = more. "
                       "A row with colour in most columns is a **recurring** pattern.")
            st.pyplot(ui_charts.monthly_heatmap(monthly, described), clear_figure=True)

            rec = monthly["recurrence"].copy()
            rec = pd.DataFrame({
                "Pattern": rec["pattern_id"] + "  " + rec["pattern"],
                "Risk": rec["risk"],
                f"Active in ({uw}s)": rec["periods_active"].astype(str) + " of " + rec["of_periods"].astype(str),
                "Recurring?": rec["recurring"].map({True: "Yes", False: "No"}),
                "First seen": rec["first_period"],
                "Log lines": rec["total_lines"].astype(int)})
            st.markdown("**Recurring or one-off?**")
            st.caption("A pattern is 'recurring' when it is active in at least half of all " + uw + "s (and there are at least two).")
            st.dataframe(rec, hide_index=True, use_container_width=True)
            st.download_button(f"⬇ Download the {ADJ[uw]} report (CSV)", export_monthly_csv(monthly),
                               f"{ADJ[uw]}_report.csv", "text/csv", key="dl_monthly_tab")

    # ================= Watch list
    with tab_watch:
        st.subheader("Who to look at first")
        if len(res["watch"]):
            st.caption("The most active sources inside High and Medium risk patterns.")
            st.dataframe(res["watch"], hide_index=True, use_container_width=True)
        else:
            st.info("This log has no IP addresses (or none fall in risky patterns), so there is no IP watch list.")
        st.subheader("Most unusual groups")
        st.caption("The groups that fit their pattern worst. A score above 1 means further from the pattern's centre "
                   "than 99% of its other groups - rare behaviour is worth a manual look.")
        st.dataframe(res["unusual"], hide_index=True, use_container_width=True)

    # ================= Reliability
    with tab_rel:
        st.subheader("Can you trust these patterns?")
        st.caption("Honest checks of the analysis itself. Good / Fair / Weak is a simple reading of each number.")
        colour_of = {"Good": "#1baf7a", "Fair": "#eda100", "Weak": "#e34948"}
        for r in res["reliability"]:
            st.markdown(
                f'<div class="rel"><div><b>{esc(r["name"])}</b><div class="muted">{esc(r["help"])}</div></div>'
                f'<div class="rel-v">{r["value"]} <span class="badge" style="background:{colour_of[r["label"]]};'
                f'color:{"#0b0b0b" if r["label"] == "Fair" else "#fff"}">{r["label"]}</span></div></div>',
                unsafe_allow_html=True)
        st.caption("Patterns are hints for a human analyst, not verdicts. Names and risk labels come from simple rules.")

    # ---- downloads (always visible, below the tabs)
    st.subheader("Take your results with you")
    dcols = st.columns(4 if monthly is not None else 3)
    if ss.report_html is None:                       # built once after the analysis; rebuilt here only if that failed
        try:
            ss.report_html = make_report_html(res, ss.file_name)
        except Exception:
            ss.report_html = None
    dcols[0].download_button("⬇ Full report (HTML)", ss.report_html or b"", "security_log_report.html",
                             "text/html", use_container_width=True, type="primary", disabled=ss.report_html is None,
                             help="One file with all results and charts. Open it in any browser, or print it to PDF.")
    dcols[1].download_button("⬇ Groups + pattern (CSV)", export_units_csv(res), "groups_with_patterns.csv",
                             "text/csv", use_container_width=True, help="Every group with the pattern it belongs to.")
    dcols[2].download_button("⬇ Pattern library (JSON)", json.dumps(lib, indent=2, default=str), "pattern_library.json",
                             "application/json", use_container_width=True,
                             help="Technical file with all patterns - can be re-used on new logs with assign_new.py.")
    if monthly is not None:
        dcols[3].download_button("⬇ Monthly report (CSV)", export_monthly_csv(monthly), "monthly_report.csv",
                                 "text/csv", use_container_width=True, key="dl_monthly_bottom")
    st.write("")
    if st.button("↺ Start over with another file", key="restart"):
        reset_all()
        st.rerun()

# ------------------------------------------------------------------ footer
st.divider()
with st.expander("What do these words mean?"):
    for term, text in GLOSSARY.items():
        st.markdown(f"**{term}** - {text}")
st.caption("🔒 Privacy: your file is processed in memory while you use this page and is not stored. "
           "Patterns are hints for a human analyst, not proof of an attack.")
