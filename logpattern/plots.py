"""
plots.py  -  simple charts that explain the result. Colours follow a validated palette:
patterns P1..P8 use the 8 categorical colours in fixed order (P9+ fold into grey "Other"),
one-colour charts use blue, and the heatmap uses blue - grey - red (low / average / high).
"""
import textwrap
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from sklearn.decomposition import PCA

SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
OTHER = "#898781"
DIVERGING = LinearSegmentedColormap.from_list("div", ["#2a78d6", "#f0efec", "#e34948"])

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": AXIS, "axes.labelcolor": INK2, "xtick.color": MUTED, "ytick.color": MUTED,
    "text.color": INK, "font.family": "sans-serif", "font.size": 10,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True,
})


def color_for(index):
    return SERIES[index] if index < len(SERIES) else OTHER


def _short(name, n=60, lines=2):
    """Wrap a long pattern name over up to `lines` lines instead of cutting it off."""
    return textwrap.fill(textwrap.shorten(name, n * lines, placeholder="..."), n)


def plot_model_selection(km_table, db_table, model_info, path):
    """Silhouette score for each k (K-Means) and the best allowed DBSCAN as a reference line."""
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(km_table["k"], km_table["silhouette"], color=SERIES[0], lw=2, marker="o", ms=7,
            markeredgecolor=SURFACE, markeredgewidth=2)
    ax.set_xlabel("Number of clusters (k)")
    ax.set_ylabel("Silhouette score (higher = better)")
    ax.set_xticks(km_table["k"])
    ax.grid(axis="x", visible=False)
    ok = db_table[(db_table["n_clusters"] >= 3) & (db_table["n_clusters"] <= 15) & (db_table["noise_ratio"] <= 0.2)]
    if len(ok):
        best = ok["silhouette"].max()
        ax.axhline(best, color=MUTED, lw=1.5, ls="--")
        ax.text(km_table["k"].max(), best, f"best allowed DBSCAN {best:.2f} ", ha="right", va="bottom",
                color=INK2, fontsize=9)
    if model_info["algorithm"] == "kmeans":
        row = km_table[km_table["k"] == model_info["k"]].iloc[0]
        ax.annotate(f"chosen: k={model_info['k']}", (row["k"], row["silhouette"]), xytext=(0, 14),
                    textcoords="offset points", ha="center", color=INK, fontsize=10, fontweight="bold")
    ax.set_title("Choosing the clustering model", loc="left", color=INK, fontsize=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_pattern_sizes(library, path):
    """Horizontal bars: how many units fall in each pattern (one colour, direct labels)."""
    pats = library["patterns"][::-1]
    fig, ax = plt.subplots(figsize=(10, 0.75 * len(pats) + 1.4))
    y = np.arange(len(pats))
    ax.barh(y, [p["size"] for p in pats], color=SERIES[0], height=0.62)
    ax.set_yticks(y)
    ax.set_yticklabels([f'{p["id"]}  {_short(p["name"], 40)}' for p in pats], fontsize=9, color=INK2)
    for yi, p in zip(y, pats):
        ax.text(p["size"], yi, f'  {p["size"]:,} ({100 * p["share"]:.1f}%)', va="center", color=INK2, fontsize=9)
    ax.set_xlim(0, max(p["size"] for p in pats) * 1.28)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("Number of units in the pattern")
    ax.set_title("Pattern library - size of each pattern", loc="left", color=INK, fontsize=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_pattern_map(Z, labels, library, path, max_points=8000):
    """Small multiples: the same 2-D picture (PCA) of all units, one panel per pattern."""
    rng = np.random.default_rng(0)
    idx = rng.choice(len(Z), min(max_points, len(Z)), replace=False)
    xy = PCA(n_components=2, random_state=0).fit_transform(Z)[idx]
    lab = labels[idx]
    pats = library["patterns"]
    n = len(pats)
    cols = 4 if n > 6 else 3
    rows = int(np.ceil(n / cols))
    fig, axes = plt.subplots(rows, cols, figsize=(3.1 * cols, 2.7 * rows), sharex=True, sharey=True)
    axes = np.atleast_1d(axes).ravel()
    for ax, p in zip(axes, pats):
        ax.scatter(xy[:, 0], xy[:, 1], s=4, color="#d6d4cc", linewidths=0)
        m = lab == p["cluster"]
        ax.scatter(xy[m, 0], xy[m, 1], s=7, color=SERIES[0], edgecolors=SURFACE, linewidths=0.3)
        ax.set_title(f'{p["id"]} - {p["size"]:,} units', fontsize=9, color=INK, loc="left")
        ax.grid(False)
        ax.set_xticks([]); ax.set_yticks([])
    for ax in axes[n:]:
        ax.axis("off")
    fig.suptitle("Where each pattern sits (2-D view of all units, PCA)", x=0.01, ha="left",
                 fontsize=12, fontweight="bold", color=INK)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_profile_heatmap(library, path):
    """What makes each pattern different: feature value vs the dataset average (z-score)."""
    feats = library["features"]
    pats = library["patterns"]
    data = np.array([[p["z_profile"][f] for f in feats] for p in pats])
    lim = max(1.5, float(np.abs(data).max()))
    fig, ax = plt.subplots(figsize=(1.0 * len(feats) + 3.6, 0.55 * len(pats) + 1.8))
    im = ax.imshow(data, cmap=DIVERGING, vmin=-lim, vmax=lim, aspect="auto")
    ax.set_xticks(range(len(feats)))
    ax.set_xticklabels([f.replace("_", "\n") for f in feats], fontsize=8, color=INK2)
    ax.set_yticks(range(len(pats)))
    ax.set_yticklabels([f'{p["id"]}  {_short(p["name"], 36)}' for p in pats], fontsize=8, color=INK2)
    ax.grid(False)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            ax.text(j, i, f"{data[i, j]:+.1f}", ha="center", va="center", fontsize=8,
                    color="white" if abs(data[i, j]) > 0.65 * lim else INK)
    cb = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cb.set_label("below average  <  0  >  above average", color=INK2, fontsize=8)
    cb.outline.set_visible(False)
    ax.set_title("What makes each pattern different (z-score of every feature)", loc="left",
                 color=INK, fontsize=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def pattern_timeline_table(units, pattern_ids):
    """Units per time period and pattern (daily / weekly / monthly, chosen from the time span)."""
    t = units["t_start"]
    if t.notna().sum() == 0:
        return None
    span = (t.max() - t.min()).days
    freq, label = ("D", "day") if span <= 45 else (("W", "week") if span <= 400 else ("M", "month"))
    period = t.dt.to_period(freq).dt.start_time
    table = pd.crosstab(period, pd.Series(pattern_ids, index=units.index))
    table = table.reindex(pd.date_range(period.min(), period.max(), freq={"D": "D", "W": "W-MON", "M": "MS"}[freq]),
                          fill_value=0) if freq == "D" else table
    table.attrs["freq"] = label
    return table


def plot_timeline(units, pattern_ids, library, path):
    """Stacked bars over time: do the patterns keep coming back? (skipped if the log has no time)"""
    table = pattern_timeline_table(units, pattern_ids)
    if table is None or len(table) < 2:
        return None
    order = [p["id"] for p in library["patterns"]]
    names = {p["id"]: p["name"] for p in library["patterns"]}
    cols = [c for c in order if c in table.columns]
    fig, ax = plt.subplots(figsize=(12.5, 5))
    bottom = np.zeros(len(table))
    width = (table.index[1] - table.index[0]).days * 0.85
    for i, c in enumerate(cols):
        vals = table[c].values
        ax.bar(table.index, vals, bottom=bottom, width=width, color=color_for(order.index(c)),
               edgecolor=SURFACE, linewidth=1.2, label=f"{c}  {_short(names[c], 52)}")
        bottom += vals
    ax.set_ylabel(f"Units per {table.attrs['freq']}")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="center left", bbox_to_anchor=(1.01, 0.5), frameon=False, fontsize=8, labelcolor=INK2)
    ax.set_title("New units per %s, by pattern (a unit is counted when it first appears)" % table.attrs["freq"], loc="left", color=INK, fontsize=12,
                 fontweight="bold")
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    table.to_csv(str(path).replace(".png", ".csv"))
    return table
