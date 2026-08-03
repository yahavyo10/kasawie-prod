# netwatch

Two-phase anomaly investigation tool:

- **Phase 1** — given an Elastic anomaly window (thousands of raw logs), pinpoint the
  specific device (IP + offending message) responsible, using cheap per-device statistical
  aggregation to shortlist candidates, then an LLM call to pick and explain the winner.
- **Phase 2** — given the 2 windows before the anomaly, build a device-scoped timeline,
  run it through deterministic attack-signature pattern matching (grounded evidence —
  CVE IDs are only ever cited if they literally appear in a log line, or are matched via
  the optional CVE database below), then an LLM call synthesizes a causal narrative. The
  narrative renders directly below the identified IP, above the raw supporting log timeline.

Every step streams to the frontend live as it completes.

## Phase 3: attacker history scan (standalone)

Once you've identified an attacker IP, scroll down to the "Attacker history scan" section.
Upload a log file you've already filtered down to just that IP (e.g. an Elastic query on
source/client IP, spanning up to a year) and it will answer three questions, grounded in a
per-device breakdown and pattern matches rather than the raw text alone:
1. **How long has this IP been present** — based on earliest/latest timestamps seen.
2. **What else did it touch** — every other device it shows up on, with a per-device summary.
3. **What access does the evidence support** — read-only recon vs. authenticated user vs.
   admin/root vs. persistent backdoor, citing which matched patterns support that assessment.

This reuses the same CVE database upload (optional) as phases 1-2. It's independent of the
phase 1/2 workflow above — you can run it any time you have a filtered IP history, whether
or not you ran the anomaly localization first.

## CVE database cross-referencing (optional)

Upload a JSON file of known CVEs with symptom keywords ("indicators"), and phase 2 will
check the device's timeline against each one — this catches a known vulnerability even
when the log text never literally writes out "CVE-XXXX-XXXXX" (the realistic case, since
device logs describe symptoms, not CVE numbers). Matching is deterministic keyword search,
not an LLM guess, so every match points at the exact indicator word and log line that
triggered it — no hallucinated CVE attributions.

Format (bare list, or `{"cves": [...]}`):
```json
[
  {
    "cve_id": "CVE-2024-21762",
    "product": "Fortinet FortiOS SSL-VPN",
    "description": "Out-of-bounds write in sslvpnd allowing remote code execution",
    "indicators": ["ssl-vpn", "out-of-bounds write", "sslvpnd"]
  }
]
```
A CVE counts as matched if at least one of its `indicators` appears (case-insensitive
substring match) anywhere in the device's log messages. A ready-to-use example with 8
real network-device CVEs is bundled at `backend/sample_data/cve_database.json`. This
upload is entirely optional — everything works exactly as before if you skip it.

## Before you do anything else: confirm you're on the latest build

Open http://localhost:8000 and look at the small pill next to "groq connected" in the
top right — it should say `netwatch-v7-2026-08-03-sse-headers`. If it says something else, or the
page won't load at all, you're running stale files or a stale server process. Don't
troubleshoot anything else until that pill matches.

## Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Your Groq key is already in `backend/.env`. **Do not commit `.env` or push it to a public
repo** — treat it as semi-exposed since it was shared in plaintext during this build, and
rotate it in the Groq console after the hackathon if this repo goes public. `.gitignore`
already excludes `.env`.

## Run

```bash
cd backend
uvicorn main:app --reload --port 8000
```

Open http://localhost:8000 — click **"Load demo data & run"** for an instant run against
bundled sample data, or upload your own window JSON files.

## If something isn't working

1. Check the version pill (see above) — if it doesn't match `BUILD_VERSION` in
   `backend/main.py`, you're not running current code. Stop the server, delete the whole
   project folder, re-download and re-extract fresh, and start again from Setup.
2. Hard-refresh the browser tab (Cmd+Shift+R / Ctrl+Shift+R) — a regular refresh can
   still serve cached JS.
3. If re-uploading a file with the same name as before shows old results: this build
   fixes that (the file input is cleared before every picker open), but if you're
   still seeing it, you're on the old frontend — see step 1.
4. `ModuleNotFoundError` → you're running `uvicorn` from a shell where the venv isn't
   active, or dependencies were installed into a different Python than the one running
   the server. Reinstall from the same terminal/session you start the server in.

## Expected JSON shape for your real window files

Either a bare array of log objects, or `{"logs": [...]}`. Each log object can use any of
these field name variants — `aggregator.py` tries all of them:

| Canonical field | Accepted keys |
|---|---|
| timestamp | `@timestamp`, `timestamp`, `time`, `date`, `ts` |
| device IP | `device_ip`, `ip`, `source_ip`, `src_ip`, `host_ip`, `device.ip`, `host.ip`, `observer.ip`, `agent.ip`, `clientip` |
| device name | `device_name`, `hostname`, `host.name`, `observer.hostname`, `device`, `agent.name`, `host` |
| message | `message`, `msg`, `log`, `text`, `event.original`, `full_message` |
| severity | `severity`, `level`, `log_level`, `log.level`, `syslog.severity` |

New schema variant not in this list? Add the dotted path to `IP_KEYS`/`NAME_KEYS` near
the top of `backend/aggregator.py` — one line, nothing else changes.

## Where to plug in your own LLM call script

`backend/llm_client.py` has one function, `call_llm_json(system_prompt, user_prompt)`,
that every pipeline step calls. Swap its body for your own script if you have one —
keep the same signature (returns a parsed dict).

## Architecture

```
backend/
  main.py          FastAPI app, SSE streaming endpoints, serves the frontend
  pipeline.py       orchestrates phase 1 + phase 2, yields step events, condenses
                     the timeline before it goes into the phase-2 prompt
  aggregator.py     log normalization + per-device statistical scoring
  signatures.py     deterministic attack-pattern / CVE-mention matching
  cve_db.py         optional CVE database cross-referencing via keyword indicators
  attacker_history.py  phase 3: per-device footprint + span reconstruction for one IP
  llm_client.py     Groq API wrapper (your script slots in here)
  models.py         shared pydantic schemas
  sample_data/      small bundled demo window_t2 / window_t1 / window_t
frontend/
  index.html        single-file UI: uploads, live feed, results panels
```

## Deploying to Render

This repo includes `render.yaml`, so Render can set it up automatically as a Blueprint.

1. **Push this folder to a GitHub repo** (see "Getting this onto GitHub" below if you
   haven't already).
2. In the Render dashboard: **New → Blueprint**, connect the repo, Render will detect
   `render.yaml` automatically.
3. During setup, Render will prompt you for **`JUBAL_API_KEY`** — paste your Groq key
   there. It's deliberately left out of `render.yaml` (marked `sync: false`) so it's
   never committed to the repo; you set it once in Render's dashboard instead.
4. Click **Apply**. Render will run `pip install -r requirements.txt` from `backend/`
   and start the server with `uvicorn main:app --host 0.0.0.0 --port $PORT` — Render
   assigns `$PORT` itself, you don't need to set it.
5. Once deployed, open the Render-provided URL — same UI, same version pill check
   applies (`netwatch-v7-2026-08-03-sse-headers`).

**Free tier note**: Render's free web services spin down after ~15 minutes of no
traffic and take ~30-60 seconds to wake back up on the next request. If you're demoing
live at a hackathon, either upgrade to a paid instance for the day, or send a request a
minute or two before you go on stage to make sure it's warm.

**No database or persistent storage needed** — this app is fully stateless (every
investigation is driven by the files you upload in the browser each time), so the
default Render web service is all you need.

**First thing to verify after deploying**: click "Load demo data & run" and watch
whether the feed appears step-by-step (correct) or all at once after a delay (means
something in front of the app is buffering the stream). The app already sends
anti-buffering headers (`Cache-Control: no-cache, no-transform`, `X-Accel-Buffering: no`)
on every streaming response, which should be sufficient for a direct Render Web Service
setup like this one. If you do see buffering and you're using a Static Site + rewrite in
front of the service rather than hitting the Web Service directly, that extra proxy layer
is the more likely culprit — point the browser at the Web Service's own URL directly to
confirm.

### Getting this onto GitHub

If this folder isn't a git repo yet:
```bash
cd netwatch
git init
git add .
git commit -m "netwatch"
```
Then create an empty repo on GitHub and:
```bash
git remote add origin https://github.com/<your-username>/<repo-name>.git
git branch -M main
git push -u origin main
```
`.gitignore` already excludes `.env`, so your Groq key won't be pushed — you'll enter
it directly in Render's dashboard instead (step 3 above).

## Notes / things to sanity-check before demo day

- Phase 1 uses `GROQ_MODEL_FAST` = `openai/gpt-oss-20b`; phase 2 uses `GROQ_MODEL` =
  `openai/gpt-oss-120b`. Both in `.env`. `llama-3.1-8b-instant` and
  `llama-3.3-70b-versatile` were deprecated by Groq in June 2026 — don't use those.
  Check https://console.groq.com/docs/models before demo day, the lineup shifts.
- Phase 2's prompt uses a *condensed* timeline (repeated near-identical lines collapsed
  into one entry with a count), which keeps token usage roughly constant no matter how
  large your windows are — this is what keeps it under Groq's per-minute token limits
  even at 5,000-log windows. If you still hit a 413 rate-limit error, wait ~60 seconds
  between phase 1 and phase 2, or switch to the Developer tier (free, just needs a card,
  no minimum spend) for ~10x higher limits.
- Phase 2 only runs if you upload **both** prior windows alongside the anomaly window in
  the same request.
