"""
service.py  -  the one function the web page calls: analyse(file, settings) -> everything to show.
It only glues together the normal pipeline steps, so the page itself stays simple.
"""
import os
import time

import pandas as pd

from .parsers import load_events
from .pipeline import run_pipeline, load_config
from .insights import describe_all, summary_sentence, reliability

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = {"ssh": "ssh.yaml", "apache": "apache.yaml", "firewall": "firewall.yaml"}

DEFAULT_MAX_LINES = 100_000       # measured peak about 0.7 GB, which fits small free hosting plans


class UserError(Exception):
    """An error with a message that is safe and understandable to show to the user."""


def build_config(settings):
    """settings (from the page) -> the config dict the pipeline understands."""
    lt = settings["log_type"]
    if lt in CONFIG_FILE:
        cfg = load_config(os.path.join(HERE, "config", CONFIG_FILE[lt]))
        cfg.pop("path", None)
    elif lt == "csv":
        cfg = dict(name="uploaded_csv", parser="generic_csv", columns=settings.get("columns", {}))
        if settings.get("fail_values"):
            cfg["fail_values"] = settings["fail_values"]
    else:
        raise UserError("We could not tell what kind of log this is. Choose 'Other CSV file' and match the columns.")
    cfg["unit"] = settings.get("unit") or cfg.get("unit", "row")
    cfg["window_minutes"] = int(settings.get("window_minutes", 10))
    cfg["max_lines"] = int(settings["max_lines"]) if settings.get("max_lines") else None
    cfg["anonymize_ips"] = bool(settings.get("anonymize"))
    if settings.get("n_patterns"):
        cfg["n_patterns"] = int(settings["n_patterns"])
    return cfg


def analyse(file, settings, progress=lambda step, text: None):
    """Run the whole analysis. `progress(step_number, text)` is called for the friendly progress bar."""
    cfg = build_config(settings)
    if cfg["unit"] in ("client", "ip_window") and cfg["parser"] == "generic_csv" \
            and "src_ip" not in (cfg.get("columns") or {}):
        raise UserError("To group by IP address we need to know which column holds the IP address. Match it in the settings.")
    t0 = time.time()
    progress(1, "Reading your file")
    try:
        events, report = load_events(cfg, file)
    except UserError:
        raise
    except Exception as e:                     # wrong file / wrong columns
        raise UserError("We could not read this file with the chosen settings. Check the log type and, "
                        f"for a CSV file, the column matching. (Technical detail: {type(e).__name__}: {e})")
    if len(events) == 0 or report.get("lines_parsed", 0) == 0:
        raise UserError("No readable log lines were found. Is the log type correct?")
    progress(2, "Grouping events")
    steps = {"n": 2}

    def log(text):
        # the pipeline prints its steps; we move the progress bar when clustering starts
        if "chosen model" in text:
            progress(4, "Writing insights")
        elif steps["n"] == 2:
            steps["n"] = 3
            progress(3, "Finding patterns")

    try:
        res = run_pipeline(events, cfg, out_dir=None, log=log, plots_on=False, extra_eval=True)
    except ValueError as e:
        raise UserError(str(e))
    progress(4, "Writing insights")
    lib = res["library"]
    described = res["described"]
    res["read_report"] = report
    res["described"] = described
    res["summary"] = summary_sentence(described, lib, report["lines_read"])
    res["reliability"] = reliability(res["metrics"], res["metrics"].get("external_check"))
    res["seconds"] = round(time.time() - t0, 1)
    res["has_time"] = bool(res["units"]["t_start"].notna().any())
    res["watch"], res["unusual"] = watch_lists(res)
    for heavy in ("events", "Z", "km_table", "db_table"):       # free memory: the page does not need these
        res.pop(heavy, None)
    return res


def watch_lists(res, top=10):
    """Two small tables for the 'watch list': the busiest sources inside the risky patterns,
    and the groups that are furthest from their own pattern (rare / unusual)."""
    import numpy as np
    units, lib, Z, labels = res["units"], res["library"], res["Z"], res["labels"]
    risk = {d["id"]: d["risk"] for d in res["described"]}
    title = {d["id"]: d["title"] for d in res["described"]}
    u = units.assign(risk=units["pattern_id"].map(risk), title=units["pattern_id"].map(title))
    watch = pd.DataFrame()
    if u["src_ip"].notna().any():
        risky = u[u["risk"].isin(["High", "Medium"]) & u["src_ip"].notna()]
        if len(risky):
            g = risky.groupby("src_ip").agg(events=("n_events", "sum"), groups=("unit_id", "size"),
                                            pattern=("title", lambda x: x.value_counts().index[0]),
                                            risk=("risk", lambda x: "High" if (x == "High").any() else "Medium"))
            watch = g.sort_values("events", ascending=False).head(top).reset_index()
            watch.columns = ["IP address", "Log lines", "Groups", "Main pattern", "Risk"]
    cent = {p["cluster"]: (np.array(p["centroid"]), p["threshold"]) for p in lib["patterns"]}
    ratio = np.full(len(units), np.nan)
    for c, (centre, thr) in cent.items():
        m = labels == c
        ratio[m] = np.linalg.norm(Z[m] - centre, axis=1) / thr
    order = np.argsort(-np.nan_to_num(ratio, nan=-1))[:5]
    unusual = pd.DataFrame({
        "Group": units["unit_id"].values[order],
        "Pattern": units["pattern_name"].values[order],
        "Example message": units["sample_message"].astype(str).str.slice(0, 110).values[order],
        "Unusualness": np.round(ratio[order], 2)})
    return watch, unusual


def export_units_csv(res):
    units = res["units"]
    keep = ["unit_id", "src_ip", "t_start", "t_end", "pattern_id", "pattern_name", "sample_message"] + res["features"]
    return units[[c for c in keep if c in units.columns]].to_csv(index=False).encode("utf-8")
