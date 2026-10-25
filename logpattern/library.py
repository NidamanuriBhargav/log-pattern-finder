"""
library.py  -  STEP 6 of the pipeline: the PATTERN LIBRARY (the real-world output).

Every cluster becomes a "pattern" with:
  * an automatic name           e.g. "Mostly failed events, many events, high event rate"
  * size, first/last seen, active days  (does it keep recurring over the months?)
  * its typical numbers (mean / median of every feature)
  * the most common event types, top source IPs, and 3 typical example units
  * rule-based hints that point to MITRE ATT&CK techniques (hints only, not proof)
  * its centre + radius, so the library can be re-used on NEW logs

The library is saved as one JSON file. Later, `assign_to_library` reads that file,
puts every unit of a new log into the nearest pattern, and flags units that fit no
pattern as "NEW / unseen" - that is how emerging attack behaviour is spotted.
"""
import re
import json
import datetime
import numpy as np
import pandas as pd
from .cluster import make_matrix, centroids_and_thresholds

# words used to build pattern names: feature -> (phrase if high, phrase if low)
PHRASES = {
    "n_events": ("many events", "few events"),
    "duration_sec": ("long-lasting", "very short"),
    "events_per_min": ("high event rate", "low event rate"),
    "n_unique_targets": ("many different targets", "single target"),
    "n_unique_event_types": ("varied event types", "repetitive events"),
    "bytes_out": ("large data sent", "little data sent"),
    "bytes_in": ("large data received", "little data received"),
    "packets": ("many packets", "few packets"),
    "share_web": ("web ports (80/443)", None),
    "share_dns": ("DNS port 53", None),
    "share_file_sharing": ("file-sharing ports (445/139)", None),
    "share_remote_access": ("remote-access ports (SSH/RDP)", None),
    "share_other_wellknown": ("other well-known ports", None),
    "share_high_port": ("high ports (1024+)", None),
}
PROFILE_COLS = ["n_events", "duration_sec", "events_per_min", "fail_ratio", "n_unique_targets",
                "n_unique_event_types", "bytes_out", "bytes_in", "packets",
                "share_web", "share_dns", "share_file_sharing", "share_remote_access",
                "share_other_wellknown", "share_high_port"]


def fail_phrase(fail_ratio):
    if fail_ratio >= 0.6:
        return "mostly failed/blocked events"
    if fail_ratio <= 0.2:
        return "mostly successful events"
    return "mix of ok and failed events"


def clean_event(event_type, limit=48):
    """Make an event template readable inside a pattern name."""
    t = re.sub(r"[:;]?\s*<PATH>", "", event_type)
    for token, word in (("<USER>", "user"), ("<IP>", "IP"), ("<N>", "N"), ("<HOST>", "host")):
        t = t.replace(token, word)
    return t.strip()[:limit]


def pattern_name(z_profile, fail_ratio, top_event=None):
    """Name = failure level (only if it varies in this log) + the (up to) 2 features that
    stand out most from the average + the most common event type."""
    parts = [fail_phrase(fail_ratio)] if fail_ratio is not None else []
    stand_out = sorted(z_profile.items(), key=lambda kv: -abs(kv[1]))
    extra = []
    for feature, z in stand_out:
        if abs(z) < 0.5 or feature not in PHRASES:
            continue
        high, low = PHRASES[feature]
        phrase = high if z > 0 else low
        if phrase:
            extra.append(phrase)
        if len(extra) == 2:
            break
    parts += extra
    name = (parts[0].capitalize() + "".join(", " + p for p in parts[1:])) if parts else "Typical behaviour"
    if top_event and top_event[1] >= 0.4:
        name += f" - mainly '{clean_event(top_event[0])}'"
    return name


def attack_hints(raw, z, event_text=""):
    """Simple rules -> suggested attack types. These are HINTS for an analyst, not proof.
    `event_text` = the most common event types of the pattern, in lower case."""
    hints = []
    fr = raw.get("fail_ratio", 0)
    failing = fr >= 0.6
    busy = z.get("n_events", 0) > 0.5 or z.get("events_per_min", 0) > 0.5
    if failing and any(w in event_text for w in ("password", "authentication", "invalid user")):
        hints.append("Failed login attempts - possible brute force / credential guessing (MITRE T1110)")
    elif failing and busy:
        hints.append("Many repeated failed attempts at a high rate - possible brute force or automated probing (MITRE T1110, T1595)")
    if any(w in event_text for w in ("does not exist", "not found", "forbidden")):
        hints.append("Requests for missing or forbidden pages - web scanning / reconnaissance (MITRE T1595)")
    if z.get("n_unique_targets", 0) > 0.8:
        hints.append("Touches many different targets - possible scanning / discovery (MITRE T1595, T1046)")
    if failing and raw.get("share_remote_access", 0) >= 0.5:
        hints.append("Blocked remote-access ports (SSH/Telnet/RDP/VNC) - remote-service probing (MITRE T1021, T1110)")
    if failing and raw.get("share_file_sharing", 0) >= 0.5:
        hints.append("Blocked file-sharing ports (SMB 445/139) - typical scanning or worm spread (MITRE T1046, T1021.002)")
    if raw.get("bytes_out", 0) >= 100_000 and z.get("bytes_out", 0) > 1.0:
        hints.append("Large outbound transfers - worth checking for data exfiltration if unexpected (MITRE T1041, T1048)")
    if "preauth" in event_text and not failing:
        hints.append("Connections closed before any login - possible service scan (MITRE T1595, T1046)")
    if "accepted" in event_text:
        hints.append("Successful logins - confirm they are expected users (a success after many failures from one IP can mean a compromised account)")
    if failing and not hints:
        hints.append("Mostly failed or blocked - unwanted or probing traffic (MITRE T1595)")
    if not hints and fr < 0.3:
        hints.append("Looks like normal activity")
    if not hints:
        hints.append("No clear attack sign - review the examples")
    return hints[:3]


def build_library(units, events, Z, labels, features, scaler, model_info, cfg, metrics=None,
                  anonymize_fn=None):
    """Build the pattern library (a plain dict that can be saved as JSON)."""
    cent = centroids_and_thresholds(Z, labels)
    unit_label = pd.Series(labels, index=units["unit_id"].values)
    ev_label = events["unit_id"].map(unit_label)
    cols = [c for c in PROFILE_COLS if c in units.columns]
    use_fail = units["fail_ratio"].std() > 0.05     # failure level only helps naming if it varies
    order = sorted(cent, key=lambda c: -(labels == c).sum())      # biggest pattern first

    patterns = []
    for rank, c in enumerate(order, start=1):
        mask = labels == c
        members = units[mask]
        zmean = dict(zip(features, Z[mask].mean(axis=0)))
        raw_mean = {col: float(members[col].mean()) for col in cols}
        dist = np.linalg.norm(Z[mask] - cent[c]["centroid"], axis=1)
        typical = members.iloc[np.argsort(dist)[:3]]
        top_events = ev_label[ev_label == c].index
        et = events.loc[top_events, "event_type"].value_counts(normalize=True).head(3)
        top_src = members.dropna(subset=["src_ip"]).groupby("src_ip")["n_events"].sum().nlargest(3)
        if anonymize_fn:
            top_src.index = top_src.index.map(anonymize_fn)
        tg = events.loc[top_events, "target"].dropna().astype(str).value_counts().head(3)
        entry = dict(
            id=f"P{rank}", cluster=int(c),
            name=pattern_name(zmean, raw_mean.get("fail_ratio") if use_fail else None,
                              (et.index[0], float(et.iloc[0])) if len(et) else None),
            size=int(mask.sum()),
            share=float(mask.mean()),
            profile={col: dict(mean=float(members[col].mean()), median=float(members[col].median()))
                     for col in cols},
            z_profile={k: float(v) for k, v in zmean.items()},
            hints=attack_hints(raw_mean, zmean, " ".join(et.index).lower()),
            top_event_types=[dict(event_type=k, share=float(v)) for k, v in et.items()],
            top_sources=[dict(src_ip=k, events=int(v)) for k, v in top_src.items()],
            top_targets=[dict(target=k, events=int(v)) for k, v in tg.items()],
            examples=[dict(unit_id=str(r.unit_id), n_events=int(r.n_events),
                           sample_message=str(r.sample_message)[:120]) for r in typical.itertuples()],
            centroid=[float(x) for x in cent[c]["centroid"]],
            threshold=cent[c]["threshold"],
        )
        if members["t_start"].notna().any():
            entry.update(first_seen=str(members["t_start"].min()), last_seen=str(members["t_start"].max()),
                         active_days=int(members["t_start"].dt.normalize().nunique()))
        patterns.append(entry)

    library = dict(
        library_version=1,
        created=datetime.datetime.now().isoformat(timespec="seconds"),
        name=cfg.get("name", "log"), unit=cfg.get("unit"), parser=cfg.get("parser"),
        features=features, scaler=scaler, model=model_info, n_units=int(len(units)),
        metrics=metrics or {}, patterns=patterns, outliers=None,
        # the settings used to read the log, so the library can be re-applied to new logs
        config={k: v for k, v in cfg.items() if k != "path"},
    )
    if (labels == -1).any():                       # DBSCAN noise = rare behaviour
        library["outliers"] = dict(id="OUT", name="Rare / outlier behaviour (DBSCAN noise)",
                                   size=int((labels == -1).sum()), share=float((labels == -1).mean()))
    return library


def save_library(library, path):
    with open(path, "w") as f:
        json.dump(library, f, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o))


def load_library(path):
    with open(path) as f:
        return json.load(f)


def assign_to_library(units, library, chunk=20000):
    """Put every unit of a NEW log into its nearest pattern.
    If the distance is bigger than that pattern's radius, flag it as NEW / unseen."""
    units = units.copy()
    for f in library["features"]:
        if f not in units.columns:
            units[f] = 0.0
    Z, _ = make_matrix(units, library["features"], library["scaler"])
    pats = library["patterns"]
    centres = np.array([p["centroid"] for p in pats])
    radius = np.array([p["threshold"] for p in pats])
    nearest, nearest_dist = [], []
    for i in range(0, len(Z), chunk):
        block = Z[i:i + chunk]
        d = np.linalg.norm(block[:, None, :] - centres[None, :, :], axis=2)
        nearest.append(d.argmin(axis=1))
        nearest_dist.append(d.min(axis=1))
    nearest, nearest_dist = np.concatenate(nearest), np.concatenate(nearest_dist)
    out = pd.DataFrame({
        "unit_id": units["unit_id"].values,
        "pattern_id": [pats[i]["id"] for i in nearest],
        "pattern_name": [pats[i]["name"] for i in nearest],
        "distance": nearest_dist,
        "is_new": nearest_dist > radius[nearest],
    })
    out.loc[out["is_new"], "pattern_id"] = "NEW"
    out.loc[out["is_new"], "pattern_name"] = "New / unseen behaviour (fits no known pattern)"
    return out
