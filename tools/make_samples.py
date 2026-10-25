"""Creates the small sample files used by the 'Try a sample' buttons from the full public datasets.
Run once:  python tools/make_samples.py   (needs data/raw/... in place)."""
import os
import pandas as pd

os.makedirs("samples", exist_ok=True)


def head(src, dst, n):
    with open(src, errors="ignore") as f, open(dst, "w") as g:
        for i, line in enumerate(f):
            if i >= n:
                break
            g.write(line)


head("data/raw/ssh/SSH.log", "samples/sample_ssh.log", 25000)
head("data/raw/apache/Apache.log", "samples/sample_apache.log", 15000)
pd.read_csv("data/raw/firewall/log2.csv").sample(10000, random_state=1).to_csv("samples/sample_firewall.csv", index=False)
print({f: os.path.getsize("samples/" + f) // 1024 for f in os.listdir("samples")}, "KB")
