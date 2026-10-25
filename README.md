# Security Log Pattern Finder

An unsupervised pipeline that groups security logs into **recurring behaviour patterns** and saves them in a
reusable **pattern library**. It works on SSH, Apache and firewall logs, and on any CSV you map yourself.

**Domain:** Cybersecurity & AI-driven threat detection  **Keywords:** security, log, pattern, discovery, clustering, threat

## The idea in one picture

```
raw log -> 1 read -> 2 common table -> 3 clean -> 4 behaviour features -> 5 cluster -> 6 pattern library -> 7 evaluate -> 8 reuse
```

* Different log formats are turned into **one common table** (`logpattern/parsers.py`).
* Lines are grouped into **behaviour units** (a login session, a client IP, a connection) and described by a few numbers (`features.py`).
* **K-Means** and **DBSCAN** cluster the units, and a simple rule picks the better one (`cluster.py`).
* Each cluster becomes a **pattern** with a name, size, examples and a rule-based MITRE ATT&CK hint (`library.py`).
* The saved library can be applied to a **new** log (`assign_new.py`); units that fit no pattern are flagged **NEW**.
* A **web page** (`app.py`) wraps all of this in three simple sections: upload, settings, insights.

## The web page in 3 steps

```
streamlit run app.py
```

1. **Upload your log** - drag a file in (or press a sample button). The log type is detected for you.
2. **Check the settings** - everything is pre-filled; press *Find patterns*.
3. **Your insights** - an overall result banner and four key numbers, then five tabs:
   **Overview** (risk split, top things to check, activity over time), **Patterns** (every pattern with risk label and examples),
   **Monthly report** (month-by-month activity, risk, recurring vs new patterns, written findings),
   **Watch list** (busiest IPs, most unusual groups) and **How reliable?**. You can download a full HTML report
   (open in a browser or print to PDF), the monthly report CSV, the groups CSV and the pattern library.

Putting it on the internet: see **DEPLOY.md** (Streamlit Community Cloud, or your own computer/server).

## Folder structure

```
app.py            the web page (upload -> settings -> insights)
DEPLOY.md         how to put the page online
requirements.txt, .streamlit/config.toml     deployment files
samples/          three small sample logs for the "Try a sample" buttons
config/           one small YAML per log type (ssh, apache, firewall)
data/raw/         the three public datasets (optional, only for the command line / notebook)
logpattern/       the code: parsers, features, cluster, library, evaluate, plots, pipeline,
                  detect.py (guess the log type), insights.py (plain-language text), service.py (page -> pipeline)
run_pipeline.py   command line: run the whole pipeline on the three datasets
assign_new.py     command line: apply a saved library to a new log
notebooks/walkthrough.ipynb   step-by-step explanation with real outputs
outputs/          results for each log (library JSON, labelled units, charts) + summary.csv
report/           the project report (Word)
tools/make_samples.py         re-creates the sample files from the full datasets
```

## Data

Put the three files here (the unpacked originals):

| Log | File | Source |
|---|---|---|
| SSH | `data/raw/ssh/SSH.log` | Loghub, https://zenodo.org/record/3227177 (`SSH.tar.gz`) |
| Apache | `data/raw/apache/Apache.log` | Loghub, same page (`Apache.tar.gz`) |
| Firewall | `data/raw/firewall/log2.csv` | UCI "Internet Firewall Data", https://archive.ics.uci.edu/dataset/542/internet+firewall+data |

## Install and run

```bash
pip install -r requirements.txt                                 # everything for the page and the pipeline
pip install -r requirements-notebook.txt                        # only if you want the Jupyter notebook

python run_pipeline.py --all                    # all three logs (about 1.5 minutes)
python run_pipeline.py --config config/ssh.yaml # one log
python run_pipeline.py --config config/ssh.yaml --input my_other_ssh.log

python assign_new.py --library outputs/ssh/pattern_library.json --input new_ssh.log

streamlit run app.py                            # the web page
jupyter notebook notebooks/walkthrough.ipynb    # step-by-step notebook
```

## Using it on your own logs

1. **Known type** (SSH syslog, Apache error log, firewall CSV): run `run_pipeline.py --config config/<type>.yaml --input yourfile`.
2. **Any other CSV:** copy `config/firewall.yaml`, set `parser: generic_csv`, and map your column names:

```yaml
name: my_logs
parser: generic_csv
unit: ip_window          # or client / session / row
window_minutes: 10
path: my_logs.csv
columns:                 # common name: your column name
  timestamp: time
  src_ip: client
  action: result
  message: text
fail_values: [denied, failed]   # optional: action values that mean failure
```

The web page does the same with plain questions ("Which column has the IP address?") and guesses the answers for you. Set `anonymize_ips: true` to replace every IP address with
a salted hash in all results.

## What the outputs mean

* `pattern_library.json` - the patterns (name, size, first/last seen, typical numbers, top event types, examples, hints) plus the numbers needed to reuse it.
* `units_labeled.csv` - every behaviour unit with the pattern it belongs to.
* `model_comparison.csv` - scores of every K-Means / DBSCAN setting that was tried.
* Charts: `pattern_sizes.png`, `pattern_profile_heatmap.png`, `pattern_map.png`, `pattern_timeline.png`, `model_selection.png`.

## Honest limits

* Patterns are **groups of similar behaviour with hints**, not proof of an attack. Read the examples.
* Names and MITRE ATT&CK hints come from simple rules and keywords.
* The firewall dataset has no IP addresses or timestamps, so each row is its own unit and there is no time chart or monthly report.
* The monthly report needs dates: Apache spans 9 months (Jun 2005 - Feb 2006), SSH 2 months (Dec 2015 - Jan 2016, both partial). A log shorter than two calendar months is reported by week or day instead, and the page says so.
* The Apache file is an error log: only lines that mention a client IP (about 60%) can be grouped into clients.
* SSH and Apache have no ground-truth labels. Quality is judged by internal scores, stability and a stress test (the firewall action gives one real external check).
* The web page's logic was tested with a simulated Streamlit (all paths) and its charts were viewed as images, but the
  page layout itself was **not** seen in a real browser - please look at it once after the first run and tell me what to adjust.
* Free hosting has little memory (about 1 GB). The page therefore analyses at most 700,000 lines by default (use 150,000 on free hosting)
  (set `LOGPATTERN_MAX_LINES` to change it); uploads can be up to 1 GB (`.streamlit/config.toml`); the command line has no such limit.
