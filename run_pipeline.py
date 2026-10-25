"""
Command line tool.

  python run_pipeline.py --all                      # run all three logs in config/
  python run_pipeline.py --config config/ssh.yaml   # run one log
  python run_pipeline.py --config config/ssh.yaml --input my_other_ssh.log   # your own file

Results go to outputs/<name>/ (pattern_library.json, units_labeled.csv, charts ...).
"""
import argparse
import glob
import json
import os
import sys
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from logpattern.pipeline import load_config, run


def summary_row(res):
    m, rep, cfg = res["metrics"], res["read_report"], res["cfg"]
    nov = m.get("novelty_test", {})
    ext = m.get("external_check", {})
    return {
        "log": cfg["name"], "log_lines": rep["lines_read"], "events": rep["events"],
        "units": len(res["units"]), "unit_type": cfg["unit"], "features": len(res["features"]),
        "algorithm": res["model"]["algorithm"], "patterns": m["n_patterns"],
        "silhouette": round(m["silhouette"], 3), "davies_bouldin": round(m["davies_bouldin"], 3),
        "stability_ari_seeds": round(m.get("ari_other_seeds", float("nan")), 3),
        "stability_ari_80pct": round(m.get("ari_80pct_subsample", float("nan")), 3),
        "pct_new_in_newest_20pct": round(nov.get("pct_test_flagged_new", float("nan")), 2),
        "pct_stress_flagged_before": round(nov.get("pct_stress_before", float("nan")), 1),
        "pct_stress_flagged_after": round(nov.get("pct_stress_after", float("nan")), 1),
        "external_purity": round(ext["purity"], 3) if ext else "",
        "external_majority_baseline": round(ext["majority_baseline"], 3) if ext else "",
        "runtime_sec": round(sum(res["timings_sec"].values()), 1),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", help="path of one YAML config")
    ap.add_argument("--all", action="store_true", help="run every config in config/")
    ap.add_argument("--input", help="use this file instead of the path in the config")
    ap.add_argument("--out", default="outputs")
    args = ap.parse_args()
    configs = sorted(glob.glob("config/*.yaml")) if args.all else [args.config]
    if not configs or configs == [None]:
        ap.error("give --config FILE or --all")
    rows = []
    for path in configs:
        cfg = load_config(path)
        source = args.input or cfg["path"]
        if not os.path.exists(source):
            print(f"[{cfg['name']}] SKIPPED - file not found: {source}\n"
                  f"   Put the file at that path (see data/raw/PUT_DATA_HERE.txt) or use --input.\n")
            continue
        res = run(cfg, source=args.input, out_dir=os.path.join(args.out, cfg["name"]))
        rows.append(summary_row(res))
        print(f"  done: {rows[-1]['patterns']} patterns, silhouette {rows[-1]['silhouette']}, "
              f"{rows[-1]['runtime_sec']} s\n")
    if not rows:
        print("Nothing was run. Check that the data files are in data/raw/ (see README.md).")
        return
    summary = pd.DataFrame(rows)
    summary.to_csv(os.path.join(args.out, "summary.csv"), index=False)
    print(summary.T.to_string(header=False))


if __name__ == "__main__":
    main()
