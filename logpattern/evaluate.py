"""
evaluate.py  -  how do we know the patterns are any good?

1. Internal scores (silhouette, Davies-Bouldin, Calinski-Harabasz)  -> in cluster.py
2. Stability   : do we get the same patterns with another random start, or on 80% of the data?
                 (measured with the Adjusted Rand Index, 1.0 = identical grouping)
3. External    : if the log has a hidden label (firewall action) compare the clusters with it
                 AFTERWARDS (the model never saw it).
4. Novelty test: build the library on the OLDER 80% of the data, then check how much of the
                 NEWER 20% fits the known patterns and how much is flagged as new.
"""
import numpy as np
import pandas as pd
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score
from .cluster import make_matrix, fit_final, centroids_and_thresholds, SEED


def stability(Z, model_info, labels, n_seeds=4, fraction=0.8):
    """ARI between the main result and (a) re-runs with other seeds, (b) a run on 80% of the data."""
    out = {}
    if model_info["algorithm"] == "kmeans":
        scores = [adjusted_rand_score(labels, fit_final(Z, model_info, seed=SEED + s))
                  for s in range(1, n_seeds + 1)]
        out["ari_other_seeds"] = float(np.mean(scores))
    rng = np.random.default_rng(SEED)
    idx = rng.choice(len(Z), int(fraction * len(Z)), replace=False)
    sub = fit_final(Z[idx], model_info, seed=SEED + 100)
    out["ari_80pct_subsample"] = float(adjusted_rand_score(labels[idx], sub))
    return out


def external_check(units, labels, column="action_main"):
    """Compare clusters with a label that was NOT used for clustering."""
    truth = units[column].astype(str).values
    purity = pd.crosstab(labels, truth).max(axis=1).sum() / len(labels)
    table = pd.crosstab(labels, truth, normalize="index").round(3)
    return dict(
        label_column=column,
        adjusted_rand_index=float(adjusted_rand_score(truth, labels)),
        normalized_mutual_info=float(normalized_mutual_info_score(truth, labels)),
        purity=float(purity),
        majority_baseline=float(pd.Series(truth).value_counts(normalize=True).iloc[0]),
    ), table


INTENSITY_COLUMNS = ["n_events", "events_per_min", "n_unique_targets", "n_unique_event_types",
                     "bytes_out", "bytes_in", "packets"]


def novelty_test(units, features, model_info, train_fraction=0.8, intensity=10, n_stress=500):
    """Train on the older part, test on the newer part. Two questions:
    (a) how much of the newer data is flagged 'new'?  (normal drift)
    (b) if we make 500 units `intensity` times more intense (10x events, targets, bytes ...),
        does the library notice? (a stress test with known 'unusual' behaviour)"""
    ordered = units.sort_values("t_start", kind="stable") if units["t_start"].notna().any() else units
    cut = int(train_fraction * len(ordered))
    train, test = ordered.iloc[:cut], ordered.iloc[cut:]
    Z_train, scaler = make_matrix(train, features)                  # scaler learned on train only
    labels = fit_final(Z_train, model_info)
    cent = centroids_and_thresholds(Z_train, labels)
    ids = list(cent)
    centres = np.array([cent[i]["centroid"] for i in ids])
    radius = np.array([cent[i]["threshold"] for i in ids])

    def flagged(frame):
        Z, _ = make_matrix(frame, features, scaler)
        d = np.linalg.norm(Z[:, None, :] - centres[None, :, :], axis=2)
        nearest = d.argmin(axis=1)
        return d.min(axis=1) > radius[nearest]

    sample = test.sample(min(n_stress, len(test)), random_state=SEED).copy()
    stressed = sample.copy()
    for col in INTENSITY_COLUMNS:
        if col in stressed.columns:
            stressed[col] = stressed[col] * intensity
    return dict(train_units=int(len(train)), test_units=int(len(test)),
                pct_test_flagged_new=float(100 * flagged(test).mean()),
                pct_stress_before=float(100 * flagged(sample).mean()),
                pct_stress_after=float(100 * flagged(stressed).mean()),
                note=f"train = older 80%, test = newer 20%; stress = {intensity}x more intense units")
