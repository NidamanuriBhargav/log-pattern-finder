# Putting the Security Log Pattern Finder online

Two ways. **Option A is the easiest and free.** Option B is for your own server or a company cloud.

> Status of this guide: the files below were prepared and the app logic was tested, but Streamlit
> was not available in the build environment, so the **first real deployment has not been tried yet**.
> If a step fails, copy the error message and ask - most problems are one-line fixes.

---

## Option A - Streamlit Community Cloud (free, about 10 minutes)

You need a free GitHub account and a free Streamlit Community Cloud account (sign in with GitHub).

1. **Create a GitHub repository** (public or private), for example `log-pattern-finder`.
2. **Upload this whole folder** to it (the big files in `data/raw/` are ignored automatically by `.gitignore`).
   With Git installed:
   ```
   git init
   git add .
   git commit -m "Security Log Pattern Finder"
   git branch -M main
   git remote add origin https://github.com/<your-name>/log-pattern-finder.git
   git push -u origin main
   ```
   (No Git? On github.com choose *Add file -> Upload files* and drag the folder contents in. Skip `outputs/` and `report/` if the upload is too big - the page does not need them.)
3. Go to **share.streamlit.io**, press **Create app**, choose your repository, branch `main`, and main file **`app.py`**.
4. Open *Advanced settings* and choose **Python 3.12**. Press **Deploy**.
5. After 2-4 minutes you get a link like `https://<name>.streamlit.app`. Share that link.

**Limits of the free plan:** about 1 GB of memory. Set the environment variable `LOGPATTERN_MAX_LINES=150000` and `maxUploadSize = 100` there. That limits each upload to 150,000 lines,
which was measured at about 0.7 GB. Larger files: analyse the first part, or use Option B.

**Make it private:** in the app's *Settings -> Sharing* you can allow only people you invite.

---

## Option B - Your own computer or server (no extra tools, just Python)

On any computer or server with Python 3.10 or newer:

```
pip install -r requirements.txt
streamlit run app.py --server.address 0.0.0.0 --server.port 8501
```
Open `http://<that-computer's-address>:8501`. On your own PC use http://localhost:8501.

* Services that run a Python start command (Render, Railway and similar) can use the same command. Set the start command to
  `streamlit run app.py --server.address 0.0.0.0 --server.port $PORT`.
* Your own computer or server can use the full 700,000 lines and 1 GB uploads. Raise `LOGPATTERN_MAX_LINES` if you have more memory.

---

## Before you share the link - checklist

- [ ] Open the page yourself and press each *Try a sample* button once.
- [ ] Upload one of your own logs.
- [ ] Decide who may use it. Uploaded logs can contain private IP addresses and user names. The page keeps the file only in memory
      and never writes it to disk, but anyone you give the link to can upload files - use the private-sharing setting for real company logs.
- [ ] Turn on **Hide IP addresses in the results** when you show results to other people.

## Settings you may want to change

| Where | What |
|---|---|
| `.streamlit/config.toml` | `maxUploadSize` (MB) - biggest file a user can upload (default 1024 = 1 GB; free online hosting cannot handle this - lower it to 100 there) |
| environment variable `LOGPATTERN_MAX_LINES` | most lines analysed per upload (default 700,000; lower to 150,000 on free hosting) |
| `logpattern/service.py` | `DEFAULT_MAX_LINES` - the pre-selected number of lines in the slider |
