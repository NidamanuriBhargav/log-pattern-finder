"""
pipeline.py  -  runs ALL the steps in order for one log:

  1 read + 2 normalise  (parsers.py)      raw log  -> common table of events
  3 clean               (here)            optional IP anonymisation, report
  4 features            (features.py)     events   -> one row of numbers per behaviour unit
  5 cluster             (cluster.py)      K-Means + DBSCAN, pick the better one
  6 pattern library     (library.py)      name, profile, hints, save as JSON
  7 evaluate            (evaluate.py)     stability, external check, novelty test
  8 charts              (plots.py)
"""
import os
import time
import hashlib
import secrets
import numpy as np
import pandas as pd
import yaml

from .parsers import load_events, IP_RE
from .features import build_units, select_features
from .cluster import (make_matrix, search_kmeans, search_dbscan, choose_model, fit_final, scores)
from .library import build_library, save_library
from .evaluate import stability, external_check, novelty_test
from .insights import describe_all
from .monthly import build_monthly, export_monthly_csv
from . import plots


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


def anonymize_ips(events):
    """Replace every IP address by a short salted hash, everywhere it appears
    (source column, unit id and message text), so results can be shared safely.
    The salt is random and thrown away, so the hashes cannot be reversed - but the same
    IP always gets the same hash inside one run, so patterns still make sense."""
    salt = secrets.token_hex(8)

    def h(ip):
        return "ip-" + hashlib.sha256((salt + ip).encode()).hexdigest()[:8]

    def scrub(series):
        text = series.astype(str).str.replace(IP_RE.pattern, lambda m: h(m.group(0)), regex=True)
        return text.where(series.notna())

    events = events.copy()
    for col in ["src_ip", "unit_id", "message"]:
        events[col] = scrub(events[col])
    return events


def run_pipeline(events, cfg, out_dir=None, log=print, plots_on=True, extra_eval=True):
    """Steps 3-8 on an already-loaded events table. Returns a dict with everything."""
    times = {}
    t = time.time()

    def tick(name):
        nonlocal t
        times[name] = round(time.time() - t, 1)
        t = time.time()

    if cfg.get("anonymize_ips"):
        events = anonymize_ips(events)

    units = build_units(events)
    features = select_features(units, cfg)
    if len(units) < 50:
        raise ValueError(f"Only {len(units)} groups were found - too few to find patterns (we need at least 50). "
                         "Try a different 'what to group together' setting, analyse more lines, or upload a bigger file.")
    Z, scaler = make_matrix(units, features)
    tick("features")
    log(f"  {len(events):,} events -> {len(units):,} units, {len(features)} features: {features}")

    fixed_k = cfg.get("n_patterns")          # optional: the user asked for an exact number of patterns
    if fixed_k:
        km_table = search_kmeans(Z, [int(fixed_k)])
        db_table = pd.DataFrame(columns=["algorithm", "eps", "min_samples", "n_clusters",
                                         "noise_ratio", "silhouette", "davies_bouldin", "calinski_harabasz"])
        model_info = dict(algorithm="kmeans", k=int(fixed_k), silhouette=float(km_table["silhouette"].iloc[0]))
    else:
        km_table = search_kmeans(Z, range(3, 11))
        min_samples = cfg.get("dbscan_min_samples", 10 if len(units) > 20000 else 5)
        db_table = search_dbscan(Z, min_samples=min_samples)
        model_info = choose_model(km_table, db_table)
    labels = fit_final(Z, model_info)
    tick("clustering")
    log(f"  chosen model: {model_info}")

    metrics = {k: float(v) for k, v in scores(Z, labels, mask=labels != -1).items()}
    metrics["n_patterns"] = int(len(set(labels) - {-1}))
    if extra_eval:
        metrics.update(stability(Z, model_info, labels))
        metrics["novelty_test"] = novelty_test(units, features, model_info)
    external_table = None
    if cfg.get("validate_with"):
        metrics["external_check"], external_table = external_check(units, labels, "action_main")
    tick("evaluation")

    library = build_library(units, events, Z, labels, features, scaler, model_info, cfg, metrics)
    tick("library")

    id_of = {p["cluster"]: p["id"] for p in library["patterns"]}
    pattern_ids = np.array([id_of.get(int(c), "OUT") for c in labels])
    units_out = units.copy()
    units_out["pattern_id"] = pattern_ids
    units_out["pattern_name"] = units_out["pattern_id"].map({p["id"]: p["name"] for p in library["patterns"]})

    described = describe_all(library)
    monthly = build_monthly(events, units_out, described)      # None if the log has no dates
    result = dict(cfg=cfg, events=events, monthly=monthly, described=described, units=units_out, Z=Z, labels=labels, features=features,
                  km_table=km_table, db_table=db_table, model=model_info, metrics=metrics,
                  library=library, external_table=external_table, pattern_ids=pattern_ids)

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        save_library(library, os.path.join(out_dir, "pattern_library.json"))
        keep = ["unit_id", "src_ip", "t_start", "t_end", "pattern_id", "pattern_name", "sample_message"] + features
        units_out[[c for c in keep if c in units_out.columns]].to_csv(
            os.path.join(out_dir, "units_labeled.csv"), index=False)
        pd.concat([km_table, db_table]).to_csv(os.path.join(out_dir, "model_comparison.csv"), index=False)
        if external_table is not None:
            external_table.to_csv(os.path.join(out_dir, "external_check.csv"))
        if monthly is not None:
            with open(os.path.join(out_dir, "monthly_report.csv"), "wb") as f:
                f.write(export_monthly_csv(monthly))
        if plots_on:
            plots.plot_model_selection(km_table, db_table, model_info, os.path.join(out_dir, "model_selection.png"))
            plots.plot_pattern_sizes(library, os.path.join(out_dir, "pattern_sizes.png"))
            plots.plot_pattern_map(Z, labels, library, os.path.join(out_dir, "pattern_map.png"))
            plots.plot_profile_heatmap(library, os.path.join(out_dir, "pattern_profile_heatmap.png"))
            plots.plot_timeline(units_out, pattern_ids, library, os.path.join(out_dir, "pattern_timeline.png"))
            if monthly is not None:
                from . import ui_charts
                fig = ui_charts.monthly_activity(monthly)
                fig.savefig(os.path.join(out_dir, "monthly_activity.png"), dpi=130, facecolor=fig.get_facecolor())
                ui_charts.plt.close(fig)
        tick("outputs")
    result["timings_sec"] = times
    return result


def run(cfg, source=None, out_dir=None, log=print, **kw):
    """Whole pipeline from a config (reads the file named in cfg['path'], or `source`)."""
    log(f"[{cfg.get('name', 'log')}] reading and normalising ...")
    t = time.time()
    events, report = load_events(cfg, source)
    read_sec = round(time.time() - t, 1)
    result = run_pipeline(events, cfg, out_dir=out_dir, log=log, **kw)
    result["read_report"] = report
    result["timings_sec"] = {"read_and_parse": read_sec, **result["timings_sec"]}
    return result
