"""
parsers.py  -  STEP 1 and 2 of the pipeline: read a raw log and convert it
into ONE common table (the "common schema").

Every log type (SSH, Apache, firewall, your own CSV) is turned into the same
columns, so all the later steps (features, clustering, patterns) never need to
know which kind of log they are working on.

To support a new log type you only have to write one small function here
(or use the "generic_csv" parser and just map the column names in a config).
"""
import re
import numpy as np
import pandas as pd

# The common schema: every parser returns a table with exactly these columns.
COMMON_COLUMNS = [
    "timestamp",    # when the event happened (can be empty for some logs)
    "session_id",   # id of a login/connection session, if the log has one
    "src_ip",       # who did it (source IP), if the log has one
    "src_port",
    "dst_port",     # which service/port was targeted
    "target",       # what was targeted: port, user name, URL path ...
    "user",         # user name, if any
    "action",       # allow/deny, error/notice, ...
    "event_type",   # the message with numbers/IPs/names masked ("template")
    "is_fail",      # 1 = failed / denied / error event, 0 = otherwise
    "bytes_out",
    "bytes_in",
    "packets",
    "duration",     # duration in seconds if the log gives one
    "message",      # original text (shortened)
]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Words that usually mean "something went wrong / was refused".
FAIL_WORDS = ("fail", "invalid", "refused", "denied", "error", "forbidden",
              "not found", "does not exist", "break-in", "unknown", "reset",
              "unable", "drop", "did not receive")

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

# Port groups: a simple way to say "what kind of service was targeted".
PORT_GROUPS = {
    "web": [80, 443, 8080, 8443],
    "dns": [53],
    "file_sharing": [21, 137, 138, 139, 445, 2049],
    "remote_access": [22, 23, 3389, 5900],
}
PORT_GROUP_NAMES = list(PORT_GROUPS) + ["other_wellknown", "high_port"]


# ----------------------------------------------------------------------------
# small helpers shared by all parsers
# ----------------------------------------------------------------------------
def read_lines(source, max_lines=None):
    """Read text lines from a file path OR an uploaded file object.
    Only the first `max_lines` lines are kept, and the file is read line by line,
    so a huge file does not fill the computer's memory."""
    import io
    import itertools
    if isinstance(source, (str, bytes)) or hasattr(source, "__fspath__"):
        f = open(source, "r", errors="ignore")
    else:
        if hasattr(source, "seek"):
            source.seek(0)
        raw = source
        if isinstance(source.read(0), bytes):
            f = io.TextIOWrapper(raw, encoding="utf-8", errors="ignore", newline=None)
        else:
            f = raw
    try:
        it = (line.rstrip("\r\n") for line in f)
        return list(itertools.islice(it, max_lines)) if max_lines else list(it)
    finally:
        if isinstance(source, (str, bytes)) or hasattr(source, "__fspath__"):
            f.close()
        elif f is not source:
            f.detach()          # keep the uploaded file usable afterwards


def make_template(series):
    """Turn messages into templates by masking the parts that change.
    'Failed password for root from 1.2.3.4 port 22' ->
    'Failed password for <USER> from <IP> port <N>'
    Messages with the same template are the same kind of event."""
    t = series.astype(str)
    t = t.str.replace(IP_RE.pattern, "<IP>", regex=True)
    t = t.str.replace(r"([Ii]nvalid user) \S+", r"\1 <USER>", regex=True)
    t = t.str.replace(r"((?:Failed|Accepted) \w+ for) (?!invalid)\S+", r"\1 <USER>", regex=True)
    t = t.str.replace(r"for \S+ \[<IP>\]", "for <HOST> [<IP>]", regex=True)
    t = t.str.replace(r"user=\S+", "user=<USER>", regex=True)
    t = t.str.replace(r"/\S*", "<PATH>", regex=True)
    t = t.str.replace(r"\d+", "<N>", regex=True)
    return t.str.slice(0, 90)


def looks_failed(series):
    """1 if the text contains a 'failure' word, else 0."""
    pattern = "|".join(re.escape(w) for w in FAIL_WORDS)
    return series.astype(str).str.lower().str.contains(pattern, regex=True).astype(int)


def port_group(ports):
    """Map port numbers to a group name (NaN stays NaN)."""
    p = pd.to_numeric(ports, errors="coerce")
    group = pd.Series(np.where(p.isna(), None, "high_port"), index=p.index, dtype=object)
    group[(p < 1024)] = "other_wellknown"
    for name, plist in PORT_GROUPS.items():
        group[p.isin(plist)] = name
    return group


def finish_schema(df):
    """Make sure the table has every common column with sensible types."""
    for col in COMMON_COLUMNS:
        if col not in df.columns:
            df[col] = np.nan
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    for col in ["bytes_out", "bytes_in", "packets", "duration"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).clip(lower=0)
    df["is_fail"] = pd.to_numeric(df["is_fail"], errors="coerce").fillna(0).astype(int)
    df["message"] = df["message"].astype(str).str.slice(0, 200)
    return df[COMMON_COLUMNS].reset_index(drop=True)


# ----------------------------------------------------------------------------
# log type 1: SSH authentication log (syslog format)
# ----------------------------------------------------------------------------
SSH_RE = re.compile(r"^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+\w+\[(\d+)\]:\s+(.*)$")


def parse_ssh(source, cfg):
    lines = read_lines(source, cfg.get("max_lines"))
    rows = [m.groups() for m in (SSH_RE.match(l) for l in lines) if m]
    report = {"lines_read": len(lines), "lines_parsed": len(rows)}
    df = pd.DataFrame(rows, columns=["mon", "day", "time", "pid", "message"])

    # syslog has no year: start from cfg['start_year'] and add 1 when the month wraps Dec -> Jan
    month = df["mon"].map(MONTHS)
    year = int(cfg.get("start_year", 2015)) + (month.diff().fillna(0) < 0).cumsum()
    df["timestamp"] = pd.to_datetime(
        year.astype(str) + " " + df["mon"] + " " + df["day"] + " " + df["time"],
        format="%Y %b %d %H:%M:%S", errors="coerce")

    # A session = one sshd process id. PIDs get re-used after weeks, so we start a
    # new session whenever the same PID is silent for more than 10 minutes.
    df = df.sort_values(["pid", "timestamp"], kind="stable")
    gap = df.groupby("pid")["timestamp"].diff().dt.total_seconds()
    new_session = gap.isna() | (gap > 600)
    df["session_id"] = df["pid"] + "-" + new_session.cumsum().astype(str)
    df = df.sort_values("timestamp", kind="stable")

    msg = df["message"]
    df["src_ip"] = msg.str.extract(r"(\d+\.\d+\.\d+\.\d+)")[0]
    user = msg.str.extract(r"[Ii]nvalid user (\S+)")[0]
    user = user.combine_first(msg.str.extract(r"(?:Failed|Accepted) \w+ for (\S+) from")[0])
    user = user.combine_first(msg.str.extract(r"\buser=(\S+)")[0])
    df["user"] = user
    df["target"] = user
    df["event_type"] = make_template(msg)
    df["is_fail"] = looks_failed(msg)
    df["action"] = np.where(df["is_fail"] == 1, "fail", "ok")
    return finish_schema(df), report


# ----------------------------------------------------------------------------
# log type 2: Apache error log
# ----------------------------------------------------------------------------
APACHE_RE = re.compile(r"^\[([^\]]+)\] \[(\w+)\] (.*)$")


def parse_apache(source, cfg):
    lines = read_lines(source, cfg.get("max_lines"))
    rows = [m.groups() for m in (APACHE_RE.match(l) for l in lines) if m]
    report = {"lines_read": len(lines), "lines_parsed": len(rows)}
    df = pd.DataFrame(rows, columns=["ts", "level", "message"])
    df["timestamp"] = pd.to_datetime(df["ts"], format="%a %b %d %H:%M:%S %Y", errors="coerce")
    df["src_ip"] = df["message"].str.extract(r"\[client (\d+\.\d+\.\d+\.\d+)\]")[0]
    text = df["message"].str.replace(r"^\[client [\d.]+\] ", "", regex=True)
    df["target"] = text.str.extract(r":\s+(/\S*)")[0]
    df["event_type"] = make_template(text)
    df["action"] = df["level"]
    df["is_fail"] = df["level"].isin(["error", "warn"]).astype(int)
    df["message"] = text
    return finish_schema(df), report


# ----------------------------------------------------------------------------
# log type 3: firewall log in CSV form (one row = one connection)
# ----------------------------------------------------------------------------
def parse_firewall(source, cfg):
    raw = pd.read_csv(source, nrows=cfg.get("max_lines"))
    report = {"lines_read": len(raw), "lines_parsed": len(raw)}
    df = pd.DataFrame({
        "src_port": raw["Source Port"],
        "dst_port": raw["Destination Port"],
        "action": raw["Action"].astype(str),
        "bytes_out": raw["Bytes Sent"],
        "bytes_in": raw["Bytes Received"],
        "packets": raw["Packets"],
        "duration": raw["Elapsed Time (sec)"],
    })
    df["target"] = df["dst_port"].astype(str)
    df["is_fail"] = (df["action"] != "allow").astype(int)
    group = port_group(df["dst_port"])
    df["event_type"] = df["action"] + " / " + group.astype(str)
    df["message"] = ("action=" + df["action"] + " dst_port=" + df["dst_port"].astype(str)
                     + " bytes=" + raw["Bytes"].astype(str) + " packets=" + raw["Packets"].astype(str)
                     + " seconds=" + raw["Elapsed Time (sec)"].astype(str))
    return finish_schema(df), report


# ----------------------------------------------------------------------------
# log type 4: ANY other CSV - the user just maps their column names
# ----------------------------------------------------------------------------
GENERIC_FIELDS = ["timestamp", "src_ip", "src_port", "dst_port", "target", "user", "action",
                  "bytes_out", "bytes_in", "packets", "duration", "message", "session_id"]


def parse_generic_csv(source, cfg):
    """cfg['columns'] maps common names -> your column names, e.g.
         columns: {timestamp: time, src_ip: client, action: result, message: text}
    cfg['fail_values'] (optional) lists the action values that mean failure."""
    raw = pd.read_csv(source, nrows=cfg.get("max_lines"), low_memory=False)
    report = {"lines_read": len(raw), "lines_parsed": len(raw)}
    mapping = cfg.get("columns", {}) or {}
    df = pd.DataFrame(index=raw.index)
    for common, theirs in mapping.items():
        if theirs and theirs in raw.columns and common in GENERIC_FIELDS:
            df[common] = raw[theirs]
    action = df["action"].astype(str) if "action" in df else pd.Series("", index=raw.index)
    message = df["message"].astype(str) if "message" in df else pd.Series("", index=raw.index)
    fail_values = [str(v).lower() for v in cfg.get("fail_values", [])]
    if fail_values:
        df["is_fail"] = action.str.lower().isin(fail_values).astype(int)
    else:
        df["is_fail"] = looks_failed(action + " " + message)
    if "target" not in df and "dst_port" in df:
        df["target"] = df["dst_port"].astype(str)
    df["event_type"] = make_template(message if message.str.len().max() > 0 else action)
    return finish_schema(df), report


PARSERS = {
    "ssh_syslog": parse_ssh,
    "apache_error": parse_apache,
    "firewall_csv": parse_firewall,
    "generic_csv": parse_generic_csv,
}


# ----------------------------------------------------------------------------
# grouping events into "behaviour units"
# ----------------------------------------------------------------------------
def assign_units(df, cfg):
    """Decide what one behaviour unit is. We cluster units, not single lines.
       session   : all lines of one login session
       client    : all lines from one source IP
       ip_window : one source IP inside one time window (works for any log with IP + time)
       row       : every line is its own unit (logs where one row is already one connection)"""
    unit = cfg.get("unit", "row")
    if unit == "session":
        df["unit_id"] = df["session_id"]
    elif unit == "client":
        df["unit_id"] = df["src_ip"]
    elif unit == "ip_window":
        minutes = int(cfg.get("window_minutes", 10))
        window = df["timestamp"].dt.floor(f"{minutes}min").astype(str)
        df["unit_id"] = df["src_ip"] + "|" + window
        df.loc[df["src_ip"].isna() | df["timestamp"].isna(), "unit_id"] = np.nan
    else:  # row
        df["unit_id"] = np.arange(len(df)).astype(str)
    return df


def load_events(cfg, source=None):
    """Read + normalise + assign units. Returns (events, report)."""
    parser = PARSERS[cfg["parser"]]
    events, report = parser(source if source is not None else cfg["path"], cfg)
    events = assign_units(events, cfg)
    report["events"] = len(events)
    report["events_without_unit"] = int(events["unit_id"].isna().sum())
    return events, report
