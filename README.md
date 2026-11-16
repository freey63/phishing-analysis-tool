# 🛡️ AI-Assisted Phishing Analysis Tool

[![CI](https://github.com/freey63/phishing-analysis-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/freey63/phishing-analysis-tool/actions)
![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.49+-FF4B4B?logo=streamlit)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-critical)
![License](https://img.shields.io/badge/License-MIT-green.svg)

A beginner-friendly yet production-structured **SOC Analyst Project** that analyses suspicious emails, detects spoofing, extracts & defangs IOCs, maps signals to the **MITRE ATT&CK** matrix, queries VirusTotal reputation, provides an AI or offline heuristic investigation narrative, and outputs ready-to-use **SOC Incident Tickets (Jira/TheHive)** and **Perimeter Blocklists**.

Built with **Python · Streamlit · Pandas · VirusTotal API · OpenAI API · JSON**.

> **Defensive and educational use only.** This tool never opens links, never
> executes attachments, and never contacts a sender. VirusTotal/OpenAI are
> optional and opt-in per analysis.

📖 **Looking to put this project on your resume or prepare for a SOC interview?** Check out [PORTFOLIO_GUIDE.md](file:///Users/vansh/Documents/Default Project/phishing-analysis-tool/PORTFOLIO_GUIDE.md) for tailored STAR resume bullet points and top technical interview answers.

---

## 1. What it does

| # | Feature | Capability | Where it lives |
|---|---------|------------|----------------|
| 1 | Suspicious email **text** analysis | Urgency, credentials, BEC invoice lures, threats, macro requests | `core/text_analyzer.py` |
| 2 | **Header** analysis | SPF/DKIM/DMARC alignment, display-name spoofing, Return-Path mismatch, hops | `core/header_analyzer.py` |
| 3 | **URL & domain** static analysis | Punycode, typosquatting (Levenshtein), raw IPs, open redirects, shorteners | `core/url_analyzer.py` |
| 4 | **IOC extraction & defanging** | URLs, domains, IPs, emails safely neutralized (`hxxps://`, `[.]`, `[at]`) | `core/ioc_extractor.py` |
| 5 | **VirusTotal** reputation lookup | Free-tier rate limiting with backoff, 24h disk caching, private IP protection | `core/vt_client.py` |
| 6 | **MITRE ATT&CK Mapping** | Tags findings with technique IDs (T1566, T1598, T1036, T1204, T1656) | `core/models.py` |
| 7 | **AI & Heuristic explanation** | OpenAI GPT narrative with deterministic local offline SOC fallback | `core/ai_explainer.py` |
| 8 | **Risk scoring engine** | Bounded 0–100 score with category caps (Header/Body/URL/Rep/Attach) | `core/scoring.py` |
| 9 | **Investigation reports & exports** | Downloadable Markdown, JSON, Jira/TheHive SOC ticket, and DNS/Firewall blocklists | `core/report_builder.py` |
| 10 | **SOC Dashboard with History** | Time-series metrics, filterable history, and Pandas summary | `ui/page_history.py` |

### Safety rules baked into the design

- 🔒 No URL, domain, or IP from an email is ever fetched or resolved - URL checks
  are pure string/parse analysis.
- 📎 Attachments are **never opened or executed**; only name, MIME type, and size
  are inspected.
- ✉️ No email is sent, replied to, forwarded, or downloaded from a mailbox.
- 🧼 IOC values are **defanged** (`hxxps://bad[.]example`) in the UI and reports.
- 🔑 API keys live in `.env`, are never rendered, logged, or written into reports.
- ❓ **Unknown reputation is never shown as safe** - it is a separate verdict.

---

## 2. Architecture

```
                ┌──────────────────────── Streamlit UI (ui/) ────────────────────────┐
                │  Analyze  │  History dashboard  │  Settings  │  Report downloads  │
                └───────────────┬────────────────────────────────────────────────────┘
                                │
                ┌───────────────▼──────────────── core/ ─────────────────────────────┐
                │ email_parser → header_analyzer → text_analyzer                    │
                │        │                │                 │                        │
                │        └────────► ioc_extractor ◄──────────┘                       │
                │                          │                                        │
                │                   url_analyzer (static, no requests)              │
                │                          │                                        │
                │              ┌───────────┴────────────┐                           │
                │        vt_client (opt-in)     ai_explainer (opt-in)                │
                │              └───────────┬────────────┘                           │
                │                     scoring → report_builder                       │
                └──────────────────────────┬─────────────────────────────────────────┘
                                           │
                             storage/history.py → data/history.jsonl
```

Every analysis returns one typed `AnalysisResult` (`core/models.py`). The UI only
renders that object, the report builder only serialises it, and history stores it
as JSON - so the layers stay independent and testable.

---

## 3. Project structure

```
phishing-analysis-tool/
├── app.py                      # Streamlit entry point + sidebar navigation
├── config.py                   # paths, constants, .env loading, Settings dataclass
├── requirements.txt
├── .env.example                # copy to .env; never commit real keys
├── .gitignore
├── .streamlit/config.toml      # dashboard theme + no usage stats
├── README.md
│
├── core/
│   ├── models.py               # Finding, IOC, Reputation, RiskAssessment, AnalysisResult
│   ├── email_parser.py         # raw text/.eml → headers + text/HTML body + attachment metadata
│   ├── header_analyzer.py      # sender alignment, auth results, routing, date checks
│   ├── text_analyzer.py        # urgency, credential/ payment lures, secrecy, link mismatch
│   ├── ioc_extractor.py        # regex extraction + refang/defang helpers
│   ├── brands.py               # brand domains, lookalike/typosquat detection, TLD lists
│   ├── url_analyzer.py         # IP hosts, punycode, shorteners, encoded/dangerous URLs
│   ├── attachment_analyzer.py  # filename-only checks (never opens the file)
│   ├── scoring.py              # weighted, capped 0–100 score + risk band
│   ├── report_builder.py       # Markdown and JSON reports
│   ├── vt_client.py            # VirusTotal v3, TTL cache, 429/401 handling
│   ├── ai_explainer.py         # OpenAI prompt + deterministic fallback
│   ├── pipeline.py             # orchestrates the whole run (the UI calls this)
│   └── samples.py              # built-in sample catalogue
│
├── storage/
│   └── history.py              # append-only JSONL history + pandas summary
│
├── ui/
│   ├── components.py           # risk badge, finding cards, DataFrames, CSS
│   ├── page_analyze.py         # input, options, results tabs, downloads
│   ├── page_history.py         # metrics, filters, charts, saved report, delete
│   └── page_settings.py        # key status, defaults, caches, safety notes
│
├── data/
│   ├── samples/                # 4 synthetic test emails (safe, defanged)
│   ├── cache/                  # created at runtime: VirusTotal cache
│   └── history.jsonl           # created at runtime (git-ignored)
│
└── tests/                      # 48 offline tests (no API keys needed)
    ├── conftest.py
    ├── test_ioc_extractor.py
    ├── test_header_analyzer.py
    ├── test_url_analyzer.py
    ├── test_scoring.py
    ├── test_report_builder.py
    ├── test_samples.py
    ├── test_vt_client.py
    └── test_ai_explainer.py
```

---

## 4. Quick start

### Requirements

- Python **3.11+** (3.12 tested)
- No API keys required to run. VirusTotal and OpenAI are optional.

### Option A - standard Python

```bash
cd phishing-analysis-tool
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # optional; fill in keys later
streamlit run app.py
```

Open the URL Streamlit prints (usually <http://localhost:8501>).

### Option B - macOS without Python installed

macOS 15 no longer ships a usable Python. `uv` can install one without Xcode:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/streamlit run app.py
```

> In this workspace a `.venv` is already provisioned, so
> `.venv/bin/streamlit run app.py` works immediately.

### Configure API keys (optional)

```bash
cp .env.example .env
```

Edit `.env`:

```dotenv
VT_API_KEY=your_virustotal_api_key
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4o-mini
MAX_VT_LOOKUPS=4
```

- VirusTotal key: <https://www.virustotal.com/gui/my-apikey> (free tier available).
- OpenAI key: <https://platform.openai.com/api-keys>.
- Restart the app, or use **Settings → Reload .env**.

Never commit `.env`. It is already listed in `.gitignore`.

### Run the tests

```bash
source .venv/bin/activate
pytest -q
# 48 passed
```

The tests mock VirusTotal and never require a key or network connection.

---

## 5. Using the app

1. Open **🔎 Analyze**.
2. Provide an email in one of three ways:
   - **Paste email** - full source with headers works best; body-only input is accepted too.
   - **Upload .eml / .txt** - read locally, 2 MB limit.
   - **Try a sample email** - four synthetic samples with documented expected results.
3. Choose options:
   - **VirusTotal lookup** - sends only URLs/domains/IPs, never the body.
   - **AI explanation** - uses OpenAI; uncheck to keep everything offline.
   - **Let AI read the body** - off by default (privacy-sensitive).
4. Click **Run analysis**.
5. Review the tabs:
   - **Overview** - risk badge, score breakdown, message details, top findings.
   - **Findings** - every finding grouped by category, filterable by severity.
   - **IOCs & reputation** - defanged indicators, VirusTotal verdicts, vendor detections.
   - **Explanation** - AI narrative or the built-in rule-based explanation.
   - **Report** - preview and download Markdown/JSON.
6. Every completed analysis is saved automatically to **📊 History**.

### Built-in samples

| Sample | Expected | What it demonstrates |
|--------|----------|----------------------|
| `01-credential-phish.eml` | **Critical** | Lookalike sender, DMARC/SPF failure, Reply-To mismatch, hidden link text, credential request |
| `02-bec-invoice.txt` | **High** | CEO fraud: wire transfer, secrecy, free-mail Reply-To |
| `03-malware-lure.eml` | **Critical** | Shortened URL, macro-enabled `.docm` attachment, DHL brand impersonation |
| `04-legitimate-newsletter.eml` | **Low** | Control case: aligned headers, SPF/DKIM/DMARC pass, ordinary links |

---

## 6. How to test each feature

### A. Text/body analysis (no keys needed)

1. Choose **Paste email**.
2. Paste only this body:

   ```
   Dear Customer,

   We detected unauthorized login activity. Verify your account within 24 hours
   or it will be suspended permanently. Enter your password here.
   ```

3. Run. **Expected:** header section says *No email headers supplied* (Info),
   body findings include credential request (High), urgency (Medium), threat
   (Medium), generic greeting (Low); risk around Medium/High.

### B. Header analysis (no keys needed)

1. Load sample `01-credential-phish.eml`.
2. Run and open **Findings → Header**.
3. **Expected:** Reply-To domain mismatch, DMARC fail, SPF fail, Microsoft brand
   in display name; `04-legitimate-newsletter.eml` instead reports
   *SPF, DKIM and DMARC all passed*.

### C. URL/domain analysis (no keys needed)

1. Paste an email whose body contains:
   `http://203.0.113.9/login` and `https://micros0ft.com/verify`.
2. Run and inspect **URL** findings.
3. **Expected:** raw IP host (High) and lookalike `micros0ft` domain (High).
   Open **IOCs** and confirm both values are defanged.

### D. IOC extraction (no keys needed)

1. Load sample `03-malware-lure.eml`.
2. Run, open **IOCs & reputation**.
3. **Expected:** `hxxps://bit[.]ly/3xParcel`, `parcel-notify.top`, `bit.ly`,
   `198.51.100.23`, and several email addresses, each with a context snippet.

### E. VirusTotal (optional key)

1. Add `VT_API_KEY` to `.env`, reload the app.
2. Enable **VirusTotal reputation lookup**, choose **max lookups 2**, run sample 1.
3. **Expected:** verdict table is populated. A missing indicator says
   *Unknown / not verified*; a clean result says *Clean* but notes it is not proof
   of safety.
4. Run the same analysis again - results come from the 24-hour cache.
5. Test failure handling: put an invalid key in `.env`, reload, run again.
   **Expected:** lookup error row with a clear message; the analysis still completes.
6. Free-tier rate limits (HTTP 429) are retried once with backoff, then reported
   as an error - the app never crashes.

### F. AI explanation (optional key)

1. Add `OPENAI_API_KEY`, reload.
2. Enable **AI explanation** and run sample 2. **Expected:** a plain-English
   narrative under **Explanation**, labelled *AI-generated*.
3. Disable AI and run again. **Expected:** built-in explanation plus a note that
   AI was disabled. No key still yields the built-in explanation.

### G. Risk scoring

Run the samples and compare with the table above. Scores are deterministic and
explained in **Overview → Score breakdown**. With VirusTotal disabled, the risk
banner also warns that reputation is unknown.

### H. Reports

After an analysis, open **Report** and download both files.

- Markdown: risk summary, findings by severity, defanged IOC table, reputation,
  attachments, explanation, recommended actions, message details.
- JSON: the full structured result under `result`.
- **Expected:** no API key appears in either file; URLs are prefixed `hxxp`/`hxxps`.

### I. History dashboard

1. Analyse two or three different samples.
2. Open **📊 History**. **Expected:** metrics (total, high/critical, average
   score, indicators), risk bar chart, score trend, filterable table.
3. Filter by risk, search a subject, open a saved analysis, download its report.
4. Delete one analysis (confirmation checkbox required), or clear everything in
   **Settings**.

### J. Automated tests

```bash
pytest -q
```

Covers: defanging/refanging, IOC extraction and de-duplication, header spoofing,
URL heuristics, scoring caps/bands, unknown-vs-clean reputation, VirusTotal
parsing/cache/429/401/private-IP handling, report generation, AI fallback, and
end-to-end sample expectations.

---

## 7. Risk scoring model

Every finding carries a severity weight:

| Severity | Weight | Examples |
|----------|-------:|----------|
| Critical | 40 | VirusTotal malicious verdict |
| High | 20 | DMARC fail, Reply-To mismatch, credential request, brand impersonation |
| Medium | 8 | urgency, shortener, macro attachment, Return-Path mismatch |
| Low | 3 | missing Message-ID, suspicious TLD, HTTP link |
| Info | 0 | authentication passed, no headers supplied |

Category caps prevent one noisy family from dominating:

`Header 40 · Body 40 · URL 40 · Reputation 50 · Attachment 25`

The final score is capped at 100:

| Score | Risk |
|------:|------|
| 0–24 | 🟢 Low |
| 25–49 | 🟡 Medium |
| 50–74 | 🟠 High |
| 75–100 | 🔴 Critical |

The breakdown is always visible, so a score is never a black box.

### Reputation verdicts

| Verdict | Meaning |
|---------|---------|
| Malicious | ≥2 engines flagged it malicious, or malicious + suspicious |
| Suspicious | exactly 1 malicious, or ≥3 suspicious engines |
| Clean | no engines flagged it - **not proof of safety** |
| Unknown | not in VirusTotal, no data, or lookup was skipped |
| Error | network/timeout/401/429 - analysis continues |

**Unknown and Clean are deliberately different values everywhere:** in the
scoring model, the UI, and the report.

---

## 8. Privacy notes

- All parsing, heuristics, scoring, and reports happen locally.
- **VirusTotal:** only indicator strings are sent. Note that VirusTotal's free
  tier may share submitted URLs with its security community - do not submit
  confidential internal links unless your policy allows it.
- **OpenAI:** only structured findings and defanged indicators are sent by
  default. The email body is included only when you tick the consent box. Never
  enable this for real personal data without approval.
- History stores structured results (subject, sender, findings, indicators), not
  the raw email. Delete it from **Settings** at any time.
- No attachment contents are ever read into the analysis or stored.

---

## 9. Troubleshooting

| Problem | Fix |
|---------|-----|
| `python3: command not found` | Install Python 3.11+ or use the `uv` route above. |
| `streamlit: command not found` | Activate the venv: `source .venv/bin/activate`. |
| Port 8501 already in use | `streamlit run app.py --server.port 8502` |
| `.env` changes not picked up | Click **Settings → Reload .env**, or restart the app. |
| VirusTotal `401` | Invalid key, or the key lacks access. Check `VT_API_KEY`. |
| VirusTotal `429` | Free tier quota (~4/min). Reduce max lookups; cached results are reused for 24h. |
| AI text says "built-in explanation" | No key, invalid key, quota/network issue. The fallback is intentional. |
| Sample 4 scores above Low | Check that the email's `Date` is not years in the past/future - date skew adds a small finding. |
| History not saving | Ensure `data/` is writable; the folder is created automatically. |
| Charts empty | Run at least one analysis first. |
| `tldextract` seems slow the first time | It uses a bundled snapshot; no network fetch is performed. |

---

## 10. Limitations

- Header checks are **heuristics**, not live SPF/DKIM/DMARC or DNS verification.
  Authentication outcomes are read from the email's own `Authentication-Results`.
- URL "reputation" without VirusTotal is unknown. Static heuristics cannot prove
  a link is safe.
- Attachments are not detonated or sandboxed; only filenames are assessed.
- The AI explanation can be wrong or manipulated by prompt injection in email
  text; treat it as a writing aid, not a verdict.
- History is a local JSONL file intended for single-user, beginner use - not a
  multi-analyst case-management system.
- Do not use this tool as the only control for a real security decision.

---

## 11. License / attribution

Sample emails are synthetic and use reserved/documentation domains where
possible. Built for learning SOC workflows: triage → indicators → reputation →
verdict → report.
