"""
cluster.py  -  STEP 5 of the pipeline: scale the features and run two clustering
algorithms, then pick the better one.

  K-Means : needs the number of clusters (k). We try k = 3..10 and look at the scores.
  DBSCAN  : finds clusters by density; points that fit nowhere are "noise" (= rare behaviour).

Scores used to compare (no labels needed):
  silhouette        -1..1, higher is better (clusters are tight and well separated)
  davies_bouldin    lower is better
  calinski_harabasz higher is better
"""
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans, DBSCAN
from sklearn.metrics import silhouette_score, davies_bouldin_score, calinski_harabasz_score
from sklearn.neighbors import NearestNeighbors
from .features import LOG_FEATURES

SIL_SAMPLE = 5000     # silhouette is slow on big data, so we score a random sample
SEED = 42


def make_matrix(units, features, scaler=None):
    """log1p the skewed features, then standardise (mean 0, std 1).
    If `scaler` is given (from a saved library) we re-use it, so new logs are
    transformed exactly like the training logs."""
    X = units[features].astype(float).copy()
    for f in features:
        if f in LOG_FEATURES:
            X[f] = np.log1p(X[f])
    if scaler is None:
        mean = X.mean()
        scale = X.std(ddof=0).replace(0, 1)
        scaler = {"mean": mean.to_dict(), "scale": scale.to_dict()}
    mean = pd.Series(scaler["mean"])[features]
    scale = pd.Series(scaler["scale"])[features]
    Z = ((X - mean) / scale).values
    return Z, scaler


def scores(Z, labels, mask=None):
    """Internal quality scores. `mask` lets us ignore DBSCAN noise points."""
    if mask is not None:
        Z, labels = Z[mask], labels[mask]
    if len(set(labels)) < 2:
        return dict(silhouette=np.nan, davies_bouldin=np.nan, calinski_harabasz=np.nan)
    n = min(SIL_SAMPLE, len(Z))
    return dict(
        silhouette=silhouette_score(Z, labels, sample_size=n, random_state=SEED),
        davies_bouldin=davies_bouldin_score(Z, labels),
        calinski_harabasz=calinski_harabasz_score(Z, labels),
    )


def search_kmeans(Z, k_values=range(3, 11)):
    rows = []
    for k in k_values:
        km = KMeans(n_clusters=k, n_init=10, random_state=SEED).fit(Z)
        rows.append(dict(algorithm="kmeans", k=k, n_clusters=k, noise_ratio=0.0,
                         **scores(Z, km.labels_)))
    return pd.DataFrame(rows)


def pack(Z):
    """Merge identical units into unique points + counts (see run_dbscan)."""
    unique, inverse, counts = np.unique(np.round(Z, 6), axis=0,
                                        return_inverse=True, return_counts=True)
    return unique, inverse.ravel(), counts


def run_dbscan(Z, eps, min_samples, packed=None):
    """DBSCAN that is safe for logs full of identical records.
    Identical units are merged into one point with a weight (= how many there were),
    DBSCAN runs on those unique points, and the labels are copied back to every unit.
    The result is the same as plain DBSCAN but uses far less memory."""
    unique, inverse, counts = packed if packed is not None else pack(Z)
    labels = DBSCAN(eps=eps, min_samples=min_samples).fit(unique, sample_weight=counts).labels_
    return labels[inverse]


def search_dbscan(Z, min_samples=10, percentiles=(50, 75, 90), fixed_eps=(0.3, 0.6, 1.0)):
    """Try several eps values: some taken from the k-distance curve (the usual trick)
    and a few fixed ones, because standardised features usually need eps around 0.3-1."""
    packed = pack(Z)
    unique = packed[0]
    k = min(min_samples, len(unique))
    kdist = NearestNeighbors(n_neighbors=k).fit(unique).kneighbors(unique)[0][:, -1]
    eps_values = {round(max(float(np.percentile(kdist, p)), 0.1), 2) for p in percentiles}
    eps_values = sorted(eps_values | set(fixed_eps))
    rows = []
    for eps in eps_values:
        labels = run_dbscan(Z, eps, min_samples, packed)
        n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
        rows.append(dict(algorithm="dbscan", eps=eps, min_samples=min_samples,
                         n_clusters=n_clusters, noise_ratio=float((labels == -1).mean()),
                         **scores(Z, labels, mask=labels != -1)))
    return pd.DataFrame(rows)


def choose_model(km_table, db_table):
    """Simple documented rule:
    1. best K-Means = the k with the highest silhouette.
    2. DBSCAN is allowed only if it gives 3..15 clusters and at most 20% noise.
    3. The algorithm with the higher silhouette wins (K-Means wins ties)."""
    best_km = km_table.sort_values("silhouette").iloc[-1]
    ok = db_table[(db_table["n_clusters"] >= 3) & (db_table["n_clusters"] <= 15)
                  & (db_table["noise_ratio"] <= 0.20)]
    if len(ok) and ok["silhouette"].max() > best_km["silhouette"]:
        best = ok.sort_values("silhouette").iloc[-1]
        return dict(algorithm="dbscan", eps=float(best["eps"]),
                    min_samples=int(best["min_samples"]), silhouette=float(best["silhouette"]))
    return dict(algorithm="kmeans", k=int(best_km["k"]), silhouette=float(best_km["silhouette"]))


def fit_final(Z, model_info, seed=SEED):
    """Fit the chosen algorithm and return the cluster label of every unit (-1 = noise)."""
    if model_info["algorithm"] == "kmeans":
        return KMeans(n_clusters=model_info["k"], n_init=10, random_state=seed).fit_predict(Z)
    return run_dbscan(Z, model_info["eps"], model_info["min_samples"])


def centroids_and_thresholds(Z, labels, min_radius=0.5):
    """For every cluster: its centre, and the distance within which 99% of its members
    lie. A new unit farther than that from every centre is called 'new / unseen'."""
    out = {}
    for c in sorted(set(labels) - {-1}):
        pts = Z[labels == c]
        centre = pts.mean(axis=0)
        dist = np.linalg.norm(pts - centre, axis=1)
        out[int(c)] = dict(centroid=centre, threshold=max(float(np.percentile(dist, 99)), min_radius))
    return out
