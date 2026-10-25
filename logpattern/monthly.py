"""
monthly.py  -  the MONTHLY REPORT.

The project goal is to group MONTHS of security logs into recurring attack patterns, so after the
clustering we look at the result month by month:

  * how much activity each month had, and how much of it fell into risky patterns
  * which patterns were active in which month (and which ones came back again and again = "recurring")
  * which patterns appeared for the first time in a later month (= something new)
  * a short written summary of what changed from one month to the next

If a log covers less than two calendar months we fall back to weeks (or days) and say so clearly.
If it has no dates at all (like the firewall CSV) a monthly report is not possible and we say that too.
"""
import numpy as np
import pandas as pd

RISKY = ("High", "Medium")


def _period_key(ts, kind):
    if kind == "month":
        return ts.dt.to_period("M").dt.start_time
    if kind == "week":
        return ts.dt.to_period("W").dt.start_time
    return ts.dt.normalize()


def _label(ts, kind):
    return ts.strftime("%b %Y") if kind == "month" else ts.strftime("%d %b %Y")


def build_monthly(events, units, described):
    """Returns None if the log has no dates, otherwise a dict with tables + findings."""
    ev = events.dropna(subset=["unit_id", "timestamp"])
    if ev.empty:
        return None
    pat_of = units.set_index("unit_id")["pattern_id"]
    risk_of = {d["id"]: d["risk"] for d in described}
    label_of = {d["id"]: d["label"] for d in described}
    ev = ev.assign(pattern_id=ev["unit_id"].map(pat_of))
    ev = ev.dropna(subset=["pattern_id"])
    ev["risk"] = ev["pattern_id"].map(risk_of).fillna("Low")

    n_months = ev["timestamp"].dt.to_period("M").nunique()
    span_days = (ev["timestamp"].max() - ev["timestamp"].min()).days + 1
    if n_months >= 2:
        kind = "month"
    elif span_days >= 14:
        kind = "week"
    else:
        kind = "day"
    ev["period"] = _period_key(ev["timestamp"], kind)
    periods = sorted(ev["period"].unique())
    plabel = {p: _label(pd.Timestamp(p), kind) for p in periods}

    g = ev.groupby("period")
    summary = pd.DataFrame({
        "lines": g.size(),
        "groups": g["unit_id"].nunique(),
        "unique_ips": g["src_ip"].nunique(),
        "failed_share": g["is_fail"].mean() * 100,
        "days_with_data": g["timestamp"].apply(lambda s: s.dt.normalize().nunique()),
    })
    risk_lines = ev.pivot_table(index="period", columns="risk", values="unit_id", aggfunc="size", fill_value=0)
    for r in ("High", "Medium", "Low", "Normal"):
        if r not in risk_lines:
            risk_lines[r] = 0
    risk_lines = risk_lines[["High", "Medium", "Low", "Normal"]]
    summary["lines_per_active_day"] = summary["lines"] / summary["days_with_data"].clip(lower=1)
    summary["attention_share"] = (risk_lines["High"] + risk_lines["Medium"]) / summary["lines"] * 100
    summary["high_share"] = risk_lines["High"] / summary["lines"] * 100

    matrix = ev.pivot_table(index="pattern_id", columns="period", values="unit_id", aggfunc="size", fill_value=0)
    order = [d["id"] for d in described if d["id"] in matrix.index] + [i for i in matrix.index if i not in label_of]
    matrix = matrix.reindex(order)
    share = matrix / matrix.sum(axis=0) * 100
    summary["patterns_active"] = (matrix > 0).sum(axis=0)
    summary["top_pattern"] = [label_of.get(matrix[p].idxmax(), matrix[p].idxmax()) for p in summary.index]
    summary["top_pattern_id"] = [matrix[p].idxmax() for p in summary.index]

    # recurrence: in how many of the periods was each pattern active?
    rec = pd.DataFrame({
        "pattern_id": matrix.index,
        "pattern": [label_of.get(i, "Rare behaviour") for i in matrix.index],
        "risk": [risk_of.get(i, "Low") for i in matrix.index],
        "periods_active": (matrix > 0).sum(axis=1).values,
        "first_period": [plabel[(matrix.loc[i] > 0).idxmax()] for i in matrix.index],
        "total_lines": matrix.sum(axis=1).values,
    })
    rec["of_periods"] = len(periods)
    rec["recurring"] = (rec["periods_active"] >= max(2, int(np.ceil(0.5 * len(periods))))) & (len(periods) >= 2)

    findings = _findings(summary, matrix, rec, plabel, periods, kind, label_of, risk_of)
    unit_word = {"month": "month", "week": "week", "day": "day"}[kind]
    out = dict(kind=kind, unit_word=unit_word, n_periods=len(periods),
               start=ev["timestamp"].min(), end=ev["timestamp"].max(), span_days=int(span_days),
               summary=summary.rename(index=plabel), matrix=matrix.rename(columns=plabel),
               share=share.rename(columns=plabel), risk=risk_lines.rename(index=plabel),
               recurrence=rec, findings=findings, labels=[plabel[p] for p in periods])
    return out


def _pct(x):
    return f"{x:.0f}%"


def _findings(summary, matrix, rec, plabel, periods, kind, label_of, risk_of):
    """A few plain-English sentences about what happened month by month."""
    word = kind
    out = []
    s = summary
    if len(periods) >= 2:
        top = s["lines"].idxmax()
        out.append(f"**Busiest {word}:** {plabel[top]} with {int(s.loc[top, 'lines']):,} log lines "
                   f"from {int(s.loc[top, 'groups']):,} groups.")
        worst = s["high_share"].idxmax()
        out.append(f"**Riskiest {word}:** {plabel[worst]} - {_pct(s.loc[worst, 'high_share'])} of its log lines "
                   f"belong to High-risk patterns.")
        last, prev = periods[-1], periods[-2]
        change = (s.loc[last, "lines"] - s.loc[prev, "lines"]) / max(s.loc[prev, "lines"], 1) * 100
        out.append(f"**Latest {word} ({plabel[last]}) compared with {plabel[prev]}:** activity "
                   f"{'up' if change >= 0 else 'down'} {abs(change):.0f}%, and High-risk activity went from "
                   f"{_pct(s.loc[prev, 'high_share'])} to {_pct(s.loc[last, 'high_share'])} of all log lines.")
        later = []
        for pid in matrix.index:
            first = (matrix.loc[pid] > 0).idxmax()
            if first != periods[0] and matrix.loc[pid, first] >= 20:
                later.append((first, pid))
        if later:
            first, pid = sorted(later)[0]
            more = f" (and {len(later) - 1} more later)" if len(later) > 1 else ""
            out.append(f"**New behaviour:** \"{label_of.get(pid, 'Rare behaviour')}\" first appeared in {plabel[first]}{more}.")
        recurring = rec[rec["recurring"] & rec["risk"].isin(RISKY)]
        if len(recurring):
            names = ", ".join(f"\"{n}\"" for n in recurring.sort_values("total_lines", ascending=False)["pattern"].head(2))
            out.append(f"**Recurring threats:** {len(recurring)} risky pattern(s) were active in at least half of all {word}s "
                       f"(for example {names}). That points to a standing problem, not a one-off.")
        else:
            out.append(f"**Recurring threats:** none of the risky patterns appeared in half or more of the {word}s.")
        if kind == "month":
            partial = []
            for p in periods:
                days_in = pd.Timestamp(p).days_in_month
                if s.loc[p, "days_with_data"] < 0.7 * days_in:
                    partial.append(f"{plabel[p]} ({int(s.loc[p, 'days_with_data'])} of {days_in} days)")
            if partial:
                out.append("**Careful:** these months have data on fewer than 70% of their days, so their totals look "
                           "smaller than reality: " + ", ".join(partial) + ".")
    else:
        out.append("Only one period of data - nothing to compare yet.")
    if kind != "month":
        out.insert(0, f"This log covers only {len(periods)} {word}(s), less than two calendar months, "
                      f"so the report is shown by {word} instead of by month.")
    return out


def export_monthly_csv(monthly):
    """One tidy CSV: a row per period with the numbers, then the pattern-by-period line counts."""
    s = monthly["summary"].reset_index().rename(columns={"period": monthly["unit_word"]})
    s = s.drop(columns=["top_pattern_id"])
    s.columns = [monthly["unit_word"].capitalize()] + [c.replace("_", " ") for c in s.columns[1:]]
    m = monthly["matrix"].reset_index().rename(columns={"pattern_id": "Pattern"})
    return (s.round(1).to_csv(index=False) + "\n\nLog lines per pattern\n" + m.to_csv(index=False)).encode("utf-8")
