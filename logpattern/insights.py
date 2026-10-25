"""
insights.py  -  turns the technical pattern library into plain-language insights:
a risk label, a title, a one-sentence meaning and a "what to check" line for every pattern,
plus an auto-written summary and reliability labels. Everything is rule-based.
"""
import re
import numpy as np

# (keyword found in the first hint, plain title, what it means, what to check)
HINT_TEXT = [
    ("exfiltration", "Large outbound transfers",
     "These connections send out far more data than usual.",
     "Check that the destinations and the amount of data are expected."),
    ("many different targets", "Touching many different targets",
     "These sources try many different ports, pages or users in a short time - typical of scanning.",
     "Look at the top IP addresses and consider blocking them if they are not yours."),
    ("brute force or automated", "Rapid, repeated failures",
     "Lots of failed attempts at a high speed - looks automated.",
     "Check the top IP addresses; consider blocking them or adding rate limits."),
    ("failed login", "Failed login attempts",
     "Someone tried to log in and failed - possibly guessing passwords.",
     "Check the top IP addresses and make sure no account was logged in afterwards."),
    ("missing or forbidden pages", "Requests for missing or forbidden pages",
     "Visitors asked for pages that do not exist or are not allowed - often web scanners looking for weak spots.",
     "Check whether the requested pages should exist and who is asking."),
    ("remote-access ports", "Blocked remote-access attempts",
     "Connections to SSH/RDP/Telnet were blocked - someone is probing for a way in.",
     "Make sure remote-access ports are not open to the whole internet."),
    ("file-sharing ports", "Blocked file-sharing probes",
     "Connections to Windows file-sharing ports were blocked - typical of scans and worms.",
     "Confirm file sharing is not exposed to the internet."),
    ("closed before any login", "Connections dropped before login",
     "Connections opened and closed without any login - often a quick service scan.",
     "Check if the same IP addresses repeat; this is usually harmless noise."),
    ("successful logins", "Successful logins",
     "Logins that worked.",
     "Confirm these users and IP addresses are expected - a success after many failures is a warning sign."),
    ("unwanted or probing", "Mostly blocked traffic",
     "Most of these connections were refused or failed.",
     "Check the examples to see what is being blocked."),
    ("no clear attack sign", "Mixed activity, no clear warning sign",
     "A mix of successful and failed events without a typical attack signature.",
     "Look at the examples to decide if this is normal for your system."),
    ("normal activity", "Normal activity",
     "Ordinary, mostly successful traffic.",
     "Nothing to do - use it as the baseline of what is normal."),
]
RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Normal": 3}

GLOSSARY = {
    "Pattern": "A group of similar behaviour found automatically (for example 'many failed logins in a row').",
    "Group": "The thing we analyse one by one - a login session, an IP address or a connection, depending on your settings.",
    "Clarity score": "How clearly separated the patterns are (0 to 1). Higher is better.",
    "Repeatability": "If we run the analysis again with different random settings, do we get the same patterns? Higher is better.",
    "Never seen before": "A group that fits none of the saved patterns - it can be a new kind of behaviour.",
    "MITRE ATT&CK": "A public catalogue of attacker techniques. We only show a code as a hint, not as proof.",
}


def _fail(p):
    return p["profile"].get("fail_ratio", {}).get("mean", 0.0)


def describe_pattern(p):
    """-> dict(title, risk, meaning, check, mitre) for one library pattern."""
    hint = (p["hints"][0] if p.get("hints") else "").lower()
    title, meaning, check = "Unlabelled behaviour", "Review the examples to understand this pattern.", "Look at the examples below."
    for key, t, m, c in HINT_TEXT:
        if key in hint:
            title, meaning, check = t, m, c
            break
    z = p.get("z_profile", {})
    busy = z.get("n_events", 0) > 0.5 or z.get("events_per_min", 0) > 0.5
    all_hints = " ".join(p.get("hints", [])).lower()
    if "normal activity" in hint:
        risk = "Normal"
    elif "successful logins" in hint:
        risk = "Low"
    elif "exfiltration" in all_hints or "many different targets" in all_hints or \
            (("brute force" in all_hints or "automated" in all_hints) and busy):
        risk = "High"
    elif _fail(p) >= 0.6 or "forbidden" in all_hints or "closed before" in all_hints:
        risk = "Medium"
    else:
        risk = "Low"
    codes = sorted({c for h in p.get("hints", []) for c in
                    re.findall(r"T\d{4}(?:\.\d{3})?", h)})
    return dict(title=title, detail=p["name"], risk=risk, meaning=meaning, check=check, mitre=codes)


def qualifier(name):
    """The part of the technical name that tells patterns with the same title apart."""
    core = name.split(" - mainly")[0]
    parts = [x.strip() for x in core.split(",")]
    parts = [x for x in parts if not x.lower().startswith(("mostly ", "mix of "))]
    return ", ".join(parts[:2]).lower()


def describe_all(library):
    """Pattern list sorted by importance (risk first, then size), each with plain-language fields.
    `label` is a short unique name (the title, plus a qualifier when two patterns share a title)."""
    rows = []
    for p in library["patterns"]:
        d = describe_pattern(p)
        rows.append({**p, **d})
    count = {}
    for r in rows:
        count[r["title"]] = count.get(r["title"], 0) + 1
    for r in rows:
        q = qualifier(r["name"]) if count[r["title"]] > 1 else ""
        r["qual"] = q
        r["label"] = f'{r["title"]} ({q})' if q else r["title"]
    seen = {}
    for r in rows:
        seen[r["label"]] = seen.get(r["label"], 0) + 1
    for r in rows:
        if seen[r["label"]] > 1:
            r["label"] += f' [{r["id"]}]'
    rows.sort(key=lambda r: (RISK_ORDER[r["risk"]], -r["size"]))
    return rows


def cap_first(text):
    """Capitalise only the first letter (str.capitalize() would turn 'IP' into 'ip')."""
    return text[:1].upper() + text[1:]


def unit_word(unit, plural=True):
    word = {"session": "login session", "client": "visitor (IP address)", "ip_window": "IP-address time window",
            "row": "connection"}.get(unit, "group")
    if plural:
        word = {"visitor (IP address)": "visitors (IP addresses)", "IP-address time window": "IP-address time windows"}.get(word, word + "s")
    return word


def summary_sentence(described, library, n_lines):
    n = len(described)
    attn = [d for d in described if d["risk"] in ("High", "Medium")]
    share_attn = sum(d["share"] for d in attn) * 100
    share_txt = "more than 99%" if share_attn >= 99.5 else f"{share_attn:.0f}%"
    word = unit_word(library.get("unit"))
    s = f"We read {n_lines:,} log lines, grouped them into {library['n_units']:,} {word} and found {n} patterns of behaviour. "
    if not attn:
        s += "None of them looks suspicious - this log looks mostly normal."
    else:
        top = attn[0]
        s += (f"{len(attn)} of them, covering {share_txt} of all {word}, may need attention. "
              f"The most important one is \"{top['title']}\" ({top['share']*100:.0f}% of {word}).")
    return s


def reliability(metrics, external=None):
    """Plain labels (Good / Fair / Weak) with a one-line explanation each."""
    def lab(v, good, fair):
        return "Good" if v >= good else ("Fair" if v >= fair else "Weak")
    out = []
    sil = metrics.get("silhouette")
    if sil is not None:
        out.append(dict(name="Clarity of patterns", value=f"{sil:.2f}", label=lab(sil, 0.5, 0.25),
                        help="How clearly the patterns are separated from each other (0 to 1, higher is better)."))
    ari = metrics.get("ari_other_seeds")
    if ari is not None and not np.isnan(ari):
        out.append(dict(name="Repeatability", value=f"{ari:.2f}", label=lab(ari, 0.9, 0.7),
                        help="If the analysis is run again with different random settings, how much do the patterns stay the same (0 to 1)?"))
    nov = metrics.get("novelty_test", {})
    if nov.get("pct_stress_after") is not None:
        v = nov["pct_stress_after"]
        out.append(dict(name="Spotting unusual behaviour", value=f"{v:.0f}%", label=lab(v / 100, 0.8, 0.5),
                        help="We made artificial extreme groups and checked how many of them the saved patterns recognise as 'never seen before'."))
    if external:
        out.append(dict(name="Agrees with the firewall's own decision", value=f"{external['purity']*100:.0f}%",
                        label=lab(external["purity"] - external.get("majority_baseline", 0) + 0.5, 0.6, 0.5),
                        help=f"How often a pattern matches the firewall's allow/deny decision (just guessing the common answer would give {external.get('majority_baseline', 0)*100:.0f}%)."))
    return out


def overall_status(described):
    """One headline for the whole log: (label, colour key, one sentence)."""
    high = [d for d in described if d["risk"] == "High"]
    med = [d for d in described if d["risk"] == "Medium"]
    if high:
        share = sum(d["share"] for d in high) * 100
        return ("Needs attention", "High",
                f"{len(high)} pattern(s) look like attack techniques and cover {share:.0f}% of all groups.")
    if med:
        share = sum(d["share"] for d in med) * 100
        return ("Worth reviewing", "Medium",
                f"{len(med)} pattern(s) are mostly failed or blocked activity ({share:.0f}% of all groups).")
    return ("Looks normal", "Normal", "No pattern looks suspicious.")
