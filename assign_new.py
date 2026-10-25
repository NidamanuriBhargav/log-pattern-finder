"""
Use a SAVED pattern library on a NEW log.

  python assign_new.py --library outputs/ssh/pattern_library.json --input new_ssh.log

Every behaviour unit in the new log is put into its nearest known pattern. Units that are
too far from every pattern are flagged NEW (= behaviour the library has never seen).
Results are written to a CSV (default: new_log_assignments.csv).
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from logpattern.parsers import load_events
from logpattern.features import build_units
from logpattern.library import load_library, assign_to_library
from logpattern.pipeline import anonymize_ips


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", required=True, help="pattern_library.json made by run_pipeline.py")
    ap.add_argument("--input", required=True, help="the new log file")
    ap.add_argument("--out", default="new_log_assignments.csv")
    args = ap.parse_args()

    lib = load_library(args.library)
    cfg = lib["config"]                                   # same parser / unit as the training log
    events, report = load_events(cfg, args.input)
    if cfg.get("anonymize_ips"):
        events = anonymize_ips(events)
    units = build_units(events)
    result = assign_to_library(units, lib)
    result = result.merge(units[["unit_id", "src_ip", "t_start", "n_events", "sample_message"]], on="unit_id")
    result.to_csv(args.out, index=False)

    counts = result["pattern_id"].value_counts()
    print(f"{len(result):,} units from {report['events']:,} events")
    for pid, n in counts.items():
        name = result.loc[result["pattern_id"] == pid, "pattern_name"].iloc[0]
        print(f"  {pid:>4}  {n:>8,}  ({100 * n / len(result):5.1f}%)  {name[:80]}")
    print(f"\nNEW / unseen units: {int((result['pattern_id'] == 'NEW').sum()):,} "
          f"({100 * (result['pattern_id'] == 'NEW').mean():.2f}%)  -> saved to {args.out}")


if __name__ == "__main__":
    main()
