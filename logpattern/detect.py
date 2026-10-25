"""
detect.py  -  look at the first lines of an uploaded file and guess what kind of log it is,
so the user never has to answer "what kind of log is this?".
"""
import io
import re

SSH_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d\s+\S+\s+sshd\[")
APACHE_RE = re.compile(r"^\[\w{3} \w{3} +\d+ [\d:]+ \d{4}\] \[")

# friendly names shown on the page
LOG_TYPES = {
    "ssh": "SSH login log (syslog)",
    "apache": "Apache web-server error log",
    "firewall": "Firewall connection log (CSV)",
    "csv": "Other CSV file (you match the columns)",
}

# words that help us guess which column is which in "other" CSV files
COLUMN_GUESS = {
    "timestamp": ("timestamp", "time", "date", "datetime", "@timestamp", "ts"),
    "src_ip": ("src_ip", "source ip", "srcip", "source_ip", "client", "remote_addr", "ip", "src", "clientip"),
    "dst_port": ("dst_port", "destination port", "dport", "dest_port", "port"),
    "action": ("action", "result", "status", "outcome", "decision", "verdict"),
    "user": ("user", "username", "account"),
    "message": ("message", "msg", "text", "event", "description", "request", "url"),
    "bytes_out": ("bytes_out", "bytes sent", "sent", "out_bytes", "bytes"),
    "bytes_in": ("bytes_in", "bytes received", "received", "in_bytes"),
    "session_id": ("session", "session_id", "sid", "connection_id"),
}


def head_text(file, n_bytes=65536):
    """First part of the file as text (works for a path or an uploaded file; does not consume it)."""
    if isinstance(file, (str, bytes)) or hasattr(file, "__fspath__"):
        with open(file, "rb") as f:
            raw = f.read(n_bytes)
    else:
        pos = file.tell() if hasattr(file, "tell") else 0
        raw = file.read(n_bytes)
        file.seek(pos)
    return raw.decode("utf-8", errors="ignore")


def detect_log_type(text):
    """Return (key, confidence_text, header_columns). key is ssh / apache / firewall / csv / unknown."""
    lines = [l for l in text.splitlines() if l.strip()][:60]
    if not lines:
        return "unknown", "The file looks empty.", []
    n = len(lines)
    if sum(bool(SSH_RE.match(l)) for l in lines) / n >= 0.5:
        return "ssh", "Most lines look like SSH (sshd) messages.", []
    if sum(bool(APACHE_RE.match(l)) for l in lines) / n >= 0.5:
        return "apache", "Most lines look like Apache error-log entries.", []
    first = lines[0]
    if first.count(",") >= 2 and not first[0].isdigit():
        cols = [c.strip().strip('"') for c in first.split(",")]
        low = [c.lower() for c in cols]
        if "source port" in low and "destination port" in low and "action" in low:
            return "firewall", "The header matches the common firewall CSV layout.", cols
        return "csv", f"It is a CSV table with {len(cols)} columns.", cols
    return "unknown", "We could not recognise this format.", []


def guess_columns(columns, df=None):
    """Guess which of the user's CSV columns is time / IP / result ... Returns {common_name: column}.
    First by column name; if a DataFrame sample is given, also by looking at the values
    (a column full of IP addresses is probably the source IP, one full of dates the timestamp)."""
    out, used = {}, set()
    low = {c: c.lower().strip() for c in columns}
    for field, words in COLUMN_GUESS.items():
        for w in words:                                   # exact name first
            hit = next((c for c in columns if low[c] == w and c not in used), None)
            if hit:
                out[field] = hit
                used.add(hit)
                break
    if df is not None:
        import pandas as pd
        for c in columns:
            if c in used:
                continue
            sample = df[c].dropna().astype(str).head(300)
            if len(sample) == 0:
                continue
            if "src_ip" not in out and sample.str.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}").mean() > 0.8:
                out["src_ip"] = c
                used.add(c)
            elif "timestamp" not in out and not sample.str.fullmatch(r"\d+(?:\.\d+)?").all():
                parsed = pd.to_datetime(sample, errors="coerce")
                if parsed.notna().mean() > 0.8:
                    out["timestamp"] = c
                    used.add(c)
    return out


def unit_options(log_type, mapped=None):
    """Which 'what should we group together?' choices make sense for this log. {key: plain text}."""
    mapped = mapped or {}
    if log_type == "ssh":
        return {"session": "Each login session  (recommended)",
                "client": "Each visitor (IP address)",
                "ip_window": "Each IP address within a time window"}
    if log_type == "apache":
        return {"client": "Each visitor (IP address)  (recommended)",
                "ip_window": "Each IP address within a time window"}
    if log_type == "firewall":
        return {"row": "Each connection  (the only choice for this file - it has no IP addresses)"}
    opts = {}
    if "src_ip" in mapped and "timestamp" in mapped:
        opts["ip_window"] = "Each IP address within a time window  (recommended)"
    if "src_ip" in mapped:
        opts["client"] = "Each visitor (IP address)"
    if "session_id" in mapped:
        opts["session"] = "Each session"
    opts["row"] = "Each row (every line is its own group)"
    return opts
