# 🎯 SOC Analyst Portfolio & Interview Guide

This guide is designed to help you showcase the **AI-Assisted Phishing Analysis Tool** on your **Resume**, **LinkedIn**, and in **Technical Interviews** for Security Operations Center (SOC) Analyst and Information Security roles.

---

## 1. Resume Section: How to Feature This Project

Add this under your **Projects** or **Technical Experience** section on your resume.

### Variant A: Impact & Engineering Focused (Recommended)
> **AI-Assisted Phishing Analysis & Triage Engine** | *Python, Streamlit, VirusTotal API, Pandas, Regex*
> - Engineered an automated email triage platform mapping phishing indicators to **MITRE ATT&CK** techniques (T1566, T1598, T1656), reducing manual email investigation time by over 70%.
> - Implemented heuristic engines for RFC 822 header spoofing detection (SPF/DKIM/DMARC alignment, Received routing hops, Return-Path mismatch) and URL static analysis (punycode, typosquatting, raw IP hosts).
> - Architected a defensive enrichment layer with VirusTotal v3 API featuring 24-hour disk caching, RFC 1918 private IP isolation, and free-tier rate-limiting with exponential backoff.
> - Built an explainable, capped 0–100 risk scoring algorithm generating downloadable SOC incident reports, ticketing notes (Jira/TheHive), and firewall/DNS perimeter blocklists.
> - Authored an automated CI/CD pipeline using **GitHub Actions** and **pytest** with 48 unit tests ensuring 100% test pass rate.

### Variant B: Junior SOC Analyst / Triage Focused
> **SOC Incident Triage Tool: Phishing Analyzer** | *Python, Streamlit, MITRE ATT&CK, VirusTotal*
> - Developed an end-to-end phishing analysis dashboard simulating Level 1/Level 2 SOC triage workflows: ingestion, indicator extraction, reputation enrichment, scoring, and containment.
> - Automated IOC extraction and defanging (`hxxp://`, `[.]`, `[at]`) to safely handle malicious URLs, domains, and IPs without risk of accidental execution.
> - Integrated hybrid intelligence: OpenAI LLM narrative generator paired with a deterministic rule-based offline explanation engine for air-gapped environments.
> - Designed one-click export for SOC incident response notes and perimeter blocklists (CSV/Text) to accelerate incident containment.

---

## 2. LinkedIn Post Template

```text
🚀 Excited to share my latest cybersecurity project: AI-Assisted Phishing Analysis Tool!

As aspiring SOC Analysts know, phishing remains one of the top initial access vectors (MITRE ATT&CK T1566). Manual triage of headers, spoofed senders, and malicious URLs can lead to alert fatigue.

To solve this, I built a modular Python & Streamlit analysis engine that automates the triage process:
🔹 Header Analysis: Checks SPF, DKIM, and DMARC alignment, Received hops, and display name spoofing.
🔹 URL & Domain Heuristics: Identifies typosquatting, lookalike domains (Levenshtein distance), punycode, and raw IP links without ever opening untrusted links.
🔹 Defensive Threat Intelligence: Integrates with VirusTotal v3 with local caching and RFC 1918 private IP filtering.
🔹 Explainable Scoring: Generates a 0–100 risk score, maps findings to MITRE ATT&CK, and produces SOC ticketing notes and perimeter blocklists.
🔹 Automated CI/CD: 48 automated tests run via GitHub Actions.

Check out the code on GitHub: [Your GitHub URL]
#Cybersecurity #SOC #PhishingAnalysis #ThreatIntelligence #Python #BlueTeam #InfoSec
```

---

## 3. Top 5 Technical Interview Questions & Model Answers

### Q1: "Why did you implement defanging, and how does your tool handle malicious URLs safely?"
**Model Answer:**
> *"In a defensive SOC environment, operational security (OpSec) is paramount. If an analyst or report reader accidentally clicks an active hyperlink in a ticket or email, it could compromise their workstation or trigger attacker telemetry. 
> In my tool, indicators are automatically defanged—converting `http://` to `hxxp://`, `.` to `[.]`, and `@` to `[at]`. Furthermore, the URL analyzer is 100% static: it parses the URL string using `urllib.parse` and regex heuristics without ever resolving DNS or opening socket connections. Network requests are only made to trusted threat intelligence APIs (VirusTotal) when the analyst explicitly opts in."*

### Q2: "How does your tool distinguish between a 'Clean' reputation and an 'Unknown' reputation?"
**Model Answer:**
> *"One of the most dangerous mistakes in threat intelligence triage is assuming that 'no engines detected this' means an indicator is safe. 
> In my scoring model and UI, 'Unknown' and 'Clean' are completely separate states:
> - **Clean** means the indicator was queried in VirusTotal and zero vendors flagged it, but we still flag that 'Clean reputation is not proof of safety' (e.g., brand-new zero-day domains).
> - **Unknown** means the indicator has never been scanned by VirusTotal, the lookup was skipped, or a rate-limit error occurred. 
> The tool explicitly informs the analyst when an indicator is unverified, preventing false senses of security."*

### Q3: "How does your header analyzer detect sender spoofing?"
**Model Answer:**
> *"The header analyzer checks multiple authentication and alignment layers:
> 1. **SPF/DKIM/DMARC Results**: Reads authentication headers to see if the sending IP was authorized or if cryptographic signatures failed.
> 2. **Sender vs. Display Name**: Checks if a popular brand (e.g., Microsoft or PayPal) is advertised in the display name while the actual domain is untrusted.
> 3. **Reply-To & Return-Path Alignment**: In BEC attacks, attackers often keep the `From` address looking legitimate but route replies to an external attacker-controlled mailbox (`Reply-To`). My tool flags registrable domain mismatches between `From`, `Reply-To`, and `Return-Path`."*

### Q4: "How do you avoid alert fatigue and prevent one heuristic from dominating the score?"
**Model Answer:**
> *"I implemented a capped, weighted scoring model. Each finding contributes points based on its severity (Critical = 40, High = 20, Medium = 8, Low = 3). 
> However, to prevent a single noisy category from blowing out the score—for instance, an email containing 15 suspicious URLs—each category has an upper limit (e.g., Header cap = 40, Body cap = 40, URL cap = 40, Reputation cap = 50). The overall score is bounded between 0 and 100, mapped to transparent risk bands: Low (0–24), Medium (25–49), High (50–74), and Critical (75–100)."*

### Q5: "How does your tool handle API limits and privacy when querying VirusTotal and OpenAI?"
**Model Answer:**
> *"For VirusTotal, the public free tier limits requests to 4 per minute. I built a rate-limiting throttle with exponential backoff on HTTP 429, accompanied by a 24-hour disk cache. In addition, internal RFC 1918 IPs (e.g., `10.0.0.0/8`, `192.168.0.0/16`) are automatically filtered out before querying to prevent internal network topology disclosure.
> For OpenAI, privacy is preserved by default: only structured findings and defanged indicators are sent, never the raw email body, unless the user explicitly checks the opt-in consent box. If OpenAI is unavailable or no key is present, the engine automatically falls back to a deterministic, local rule-based explanation engine without crashing."*

---

## 4. Key Architectural Highlights to Mention

| Architecture Pillar | Implementation Detail |
|---|---|
| **Industry Alignment** | Direct mapping to **MITRE ATT&CK** Enterprise Matrix (T1566, T1598, T1036, T1204, T1656). |
| **Separation of Concerns** | Core parsing/scoring engine is completely decoupled from the Streamlit UI and can run headless. |
| **Persistence** | Lightweight append-only JSON Lines (`data/history.jsonl`) avoiding external DB dependencies while enabling Pandas time-series analytics. |
| **Code Quality & CI/CD** | Fully typed (PEP 484 dataclasses, enums), modular packages, and **GitHub Actions** CI running on Python 3.11 and 3.12 with 48 automated tests. |
