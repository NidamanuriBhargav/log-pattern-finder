"""Clean, consistent charts for the web page (matplotlib).
Every chart uses the same fonts, the same grey grid and the same risk colours, and puts values on the chart
so nobody has to read numbers off an axis."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap

RISK_COLOR = {"High": "#e34948", "Medium": "#eda100", "Low": "#2a78d6", "Normal": "#1baf7a"}
RISK_ORDER = ["High", "Medium", "Low", "Normal"]
SURFACE, INK, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e1e0d9"

plt.rcParams.update({"font.size": 10, "axes.titlesize": 11, "axes.edgecolor": GRID, "axes.labelcolor": MUTED,
                     "xtick.color": MUTED, "ytick.color": INK, "font.family": "DejaVu Sans"})


def short(text, n=44):
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def chart_label(d, n=40):
    """Two-line label: 'P3  Title' and, underneath, the small qualifier that tells patterns with the same title apart."""
    first = f'{d["id"]}  {short(d["title"], n)}'
    return first + (f'\n{short(d["qual"], n + 6)}' if d.get("qual") else "")


def _fig(w, h):
    fig, ax = plt.subplots(figsize=(w, h), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    return fig, ax


def _legend(ax, risks, **kw):
    handles = [plt.Rectangle((0, 0), 1, 1, color=RISK_COLOR[r]) for r in risks]
    ax.legend(handles, [f"{r} risk" for r in risks], frameon=False, fontsize=9, **kw)


# ------------------------------------------------------------------ overview
def risk_bar(described):
    """One bar split by risk level: how much of everything falls into each risk level."""
    share = {r: sum(d["share"] for d in described if d["risk"] == r) * 100 for r in RISK_ORDER}
    fig, ax = _fig(8, 1.25)
    left = 0
    for r in RISK_ORDER:
        v = share[r]
        if v <= 0:
            continue
        ax.barh([0], [v], left=left, color=RISK_COLOR[r], height=0.55)
        if v >= 6:
            ax.text(left + v / 2, 0, f"{r}\n{v:.0f}%", ha="center", va="center", fontsize=9,
                    color="#0b0b0b" if r == "Medium" else "white", fontweight="bold")
        left += v
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.5, 0.5)
    ax.axis("off")
    fig.tight_layout(pad=0.3)
    return fig


def sizes_chart(described):
    rows = list(reversed(described))
    fig, ax = _fig(8, 0.58 * len(rows) + 0.9)
    vals = [r["share"] * 100 for r in rows]
    ax.barh([chart_label(r) for r in rows], vals,
            color=[RISK_COLOR[r["risk"]] for r in rows], height=0.62)
    top = max(vals)
    for y, (v, r) in enumerate(zip(vals, rows)):
        ax.text(v + top * 0.015, y, f'{v:.1f}%   ({r["size"]:,})', va="center", fontsize=9, color=INK)
    ax.set_xlim(0, top * 1.28)
    ax.set_xlabel("Share of all groups (number of groups in brackets)")
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(axis="y", length=0)
    ax.spines["left"].set_visible(False)
    _legend(ax, [r for r in RISK_ORDER if any(x["risk"] == r for x in rows)], loc="lower right")
    fig.tight_layout()
    return fig


def activity_chart(units, described):
    """Groups over time, stacked by risk level (4 colours instead of one colour per pattern)."""
    u = units.dropna(subset=["t_start"]).copy()
    if u.empty:
        return None
    risk = {d["id"]: d["risk"] for d in described}
    u["risk"] = u["pattern_id"].map(risk).fillna("Low")
    span = (u["t_start"].max() - u["t_start"].min()).total_seconds()
    freq, label = ("h", "hour") if span <= 3 * 86400 else (("D", "day") if span <= 120 * 86400 else ("W", "week"))
    u["bin"] = u["t_start"].dt.to_period(freq).dt.start_time if freq == "W" else u["t_start"].dt.floor(freq)
    tab = u.pivot_table(index="bin", columns="risk", values="unit_id", aggfunc="size", fill_value=0)
    tab = tab.reindex(columns=[r for r in RISK_ORDER if r in tab.columns])
    if len(tab) < 2:
        return None
    fig, ax = _fig(8, 3.2)
    bottom = np.zeros(len(tab))
    width = {"h": 1 / 24, "D": 1.0, "W": 7.0}[freq] * 0.9
    for r in tab.columns:
        ax.bar(tab.index, tab[r].values, bottom=bottom, color=RISK_COLOR[r], width=width, linewidth=0)
        bottom += tab[r].values
    ax.set_ylabel(f"Groups per {label}")
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    import matplotlib.dates as mdates
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d %b" if freq != "h" else "%d %b %H:%M"))
    fig.autofmt_xdate(rotation=0, ha="center")
    _legend(ax, list(tab.columns), loc="upper left", ncol=len(tab.columns))
    fig.tight_layout()
    return fig


FRIENDLY = {"n_events": "Number of log lines", "duration_sec": "How long it lasts", "events_per_min": "Speed (lines/min)",
            "fail_ratio": "Share of failures", "n_unique_targets": "Different targets", "n_unique_event_types": "Different event kinds",
            "bytes_out": "Data sent out", "bytes_in": "Data received", "packets": "Packets",
            "share_web": "Web ports", "share_dns": "DNS port", "share_file_sharing": "File-sharing ports",
            "share_remote_access": "Remote-access ports", "share_other_wellknown": "Other known ports", "share_high_port": "High ports"}


def difference_heatmap(described, features):
    z = np.array([[d["z_profile"].get(f, 0) for f in features] for d in described])
    shown = np.clip(z, -4, 4)
    fig, ax = _fig(8, 0.6 * len(described) + 2.3)
    cmap = LinearSegmentedColormap.from_list("div", ["#2a78d6", "#f0efec", "#e34948"])
    im = ax.imshow(shown, cmap=cmap, vmin=-4, vmax=4, aspect="auto", interpolation="nearest")
    ax.set_xticks(range(len(features)))
    ax.set_xticklabels([FRIENDLY.get(f, f) for f in features], rotation=35, ha="right", fontsize=9)
    ax.set_yticks(range(len(described)))
    ax.set_yticklabels([chart_label(d, 34) for d in described], fontsize=8.5)
    for i in range(z.shape[0]):
        for j in range(z.shape[1]):
            ax.text(j, i, f"{z[i, j]:.1f}", ha="center", va="center", fontsize=8,
                    color="white" if abs(shown[i, j]) > 2.6 else INK)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    cb = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.02)
    cb.set_label("lower than average  ←  →  higher than average", fontsize=8, color=MUTED)
    cb.outline.set_visible(False)
    fig.tight_layout()
    return fig


# ------------------------------------------------------------------ monthly report
def monthly_activity(monthly):
    """Log lines per month, stacked by risk level, with the High-risk share written above each bar."""
    risk = monthly["risk"]
    labels = list(risk.index)
    fig, ax = _fig(8, 3.4)
    bottom = np.zeros(len(risk))
    for r in RISK_ORDER:
        if r in risk and risk[r].sum() > 0:
            ax.bar(labels, risk[r].values, bottom=bottom, color=RISK_COLOR[r], width=0.7, linewidth=0)
            bottom += risk[r].values
    s = monthly["summary"]
    for i, lab in enumerate(labels):
        ax.text(i, bottom[i] * 1.01, f"{bottom[i]:,.0f}\nHigh: {s.loc[lab, 'high_share']:.0f}%", ha="center", va="bottom",
                fontsize=8, color=INK)
    ax.set_ylim(0, bottom.max() * 1.22)
    ax.set_ylabel("Log lines")
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    if len(labels) > 6:
        plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    _legend(ax, [r for r in RISK_ORDER if r in risk and risk[r].sum() > 0], loc="upper left", ncol=4)
    fig.tight_layout()
    return fig


def monthly_heatmap(monthly, described):
    """Which pattern was active in which month: share of that month's log lines. Darker = more."""
    share = monthly["share"]
    label = {d["id"]: d["label"] for d in described}
    risk = {d["id"]: d["risk"] for d in described}
    ids = list(share.index)
    byid = {d["id"]: d for d in described}
    fig, ax = _fig(8, 0.6 * len(ids) + 1.6)
    cmap = LinearSegmentedColormap.from_list("seq", ["#f4f8fd", "#2a78d6", "#0b3d7a"])
    data = share.values
    im = ax.imshow(data, cmap=cmap, vmin=0, vmax=max(40, np.nanmax(data)), aspect="auto", interpolation="nearest")
    ax.set_xticks(range(len(share.columns)))
    many = len(share.columns) > 5
    ax.set_xticklabels(share.columns, rotation=30 if many else 0, ha="left" if many else "center", fontsize=9)
    ax.set_yticks(range(len(ids)))
    ax.set_yticklabels([chart_label(byid[i], 34) if i in byid else f"{i}  Rare behaviour" for i in ids], fontsize=8.5)
    for tick, i in zip(ax.get_yticklabels(), ids):
        tick.set_color(RISK_COLOR.get(risk.get(i, "Low"), INK) if risk.get(i) in ("High",) else INK)
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            v = data[i, j]
            if v >= 0.5:
                ax.text(j, i, f"{v:.0f}%", ha="center", va="center", fontsize=8,
                        color="white" if v > 0.55 * im.get_clim()[1] else INK)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    ax.xaxis.tick_top()
    fig.tight_layout()
    return fig
