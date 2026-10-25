"""
features.py  -  STEP 4 of the pipeline: turn events into BEHAVIOUR features.

We do not cluster raw log lines. We group lines into "units" (a session, a client IP,
a connection ...) and describe each unit with a few numbers that exist in almost
every security log:

    n_events              how many log lines the unit produced
    duration_sec          how long the unit was active
    events_per_min        how fast it produced events (burstiness)
    fail_ratio            share of failed / denied / error events
    n_unique_targets      how many different targets it touched (ports, users, URLs)
    n_unique_event_types  how many different kinds of event it caused
    bytes_out, bytes_in, packets   traffic size (only if the log has it)
    share_<port group>    share of traffic to web / dns / file sharing / ... ports

Features that are constant in a given log (for example bytes in an SSH log) are
removed automatically, so the SAME code works for every log type.
"""
import numpy as np
import pandas as pd
from .parsers import PORT_GROUP_NAMES, port_group

# Features with a long tail (a few huge values) get log1p() so that clustering is not
# dominated by a handful of extreme units.
LOG_FEATURES = ["n_events", "duration_sec", "events_per_min", "n_unique_targets",
                "n_unique_event_types", "bytes_out", "bytes_in", "packets"]

BASE_FEATURES = ["n_events", "duration_sec", "events_per_min", "fail_ratio",
                 "n_unique_targets", "n_unique_event_types",
                 "bytes_out", "bytes_in", "packets"]
SHARE_FEATURES = ["share_" + g for g in PORT_GROUP_NAMES]


def build_units(events):
    """One row per behaviour unit, with all candidate features."""
    ev = events.dropna(subset=["unit_id"]).copy()

    # port-group indicator columns (0/1 per event); averaged later = share per unit
    groups = port_group(ev["dst_port"])
    has_ports = groups.notna().any()
    if has_ports:
        for g in PORT_GROUP_NAMES:
            ev["share_" + g] = (groups == g).astype(float)

    agg = dict(
        src_ip=("src_ip", "first"),
        t_start=("timestamp", "min"),
        t_end=("timestamp", "max"),
        n_events=("unit_id", "size"),
        fail_ratio=("is_fail", "mean"),
        n_unique_targets=("target", "nunique"),
        n_unique_event_types=("event_type", "nunique"),
        bytes_out=("bytes_out", "sum"),
        bytes_in=("bytes_in", "sum"),
        packets=("packets", "sum"),
        logged_duration=("duration", "sum"),
        action_main=("action", "first"),
        sample_message=("message", "first"),
    )
    if has_ports:
        for g in PORT_GROUP_NAMES:
            agg["share_" + g] = ("share_" + g, "mean")

    units = ev.groupby("unit_id", sort=False).agg(**agg).reset_index()

    # duration = time between first and last event, or the duration the log itself gives
    span = (units["t_end"] - units["t_start"]).dt.total_seconds().fillna(0)
    units["duration_sec"] = np.maximum(span, units["logged_duration"])
    units["events_per_min"] = units["n_events"] / (units["duration_sec"] / 60 + 1)
    return units.drop(columns=["logged_duration"])


def select_features(units, cfg=None):
    """Keep only features that actually vary in this log (and are not excluded)."""
    cfg = cfg or {}
    exclude = set(cfg.get("exclude_features", []))
    # if every unit has the same number of events (e.g. 1 row = 1 connection), the
    # "events per minute" number only repeats the duration, so we skip it
    if units["n_events"].std() == 0:
        exclude.add("events_per_min")
    chosen = []
    for f in BASE_FEATURES + SHARE_FEATURES:
        if f in units.columns and f not in exclude and units[f].std() > 0:
            chosen.append(f)
    return chosen
