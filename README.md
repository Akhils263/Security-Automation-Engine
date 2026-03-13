# Modular Threat Intelligence & IP Enrichment Engine

> Automates the core SOC analyst workflow — takes a file of indicators, enriches them via OTX AlienVault, scores their threat level, and outputs a PDF report.

---

## Overview

Given a file of indicators (IP addresses, file hashes, domains, or URLs), this tool:

1. Auto-detects the indicator type
2. Checks a local cache before hitting the API
3. Enriches each indicator via the [OTX AlienVault API](https://otx.alienvault.com/)
4. Calculates a threat score from 0–100
5. Stores results locally for future lookups
6. Outputs a structured PDF threat intelligence report

---

## Pipeline

```
Input File → Type Detection → Cache Check → OTX API Enrichment → Score Calculation → Store → PDF Report
```

---

## Project Structure

```
├── main.py            # Entry point — runs process_log and generates report
├── enrichment.py      # Core logic: type detection, API calls, scoring, batch processing
├── db.py              # Database: store and lookup indicators
├── report.py          # PDF report generation
└── targets.txt        # Input file with one indicator per line
```

---

## Core Functions

| Function | File | Description |
|----------|------|-------------|
| `identify_ioc_type(indicator)` | enrichment.py | Auto-detects type: IPv4, Domain, URL, FileHash-SHA256, FileHash-MD5 |
| `enrich_ip_otx(ip)` | enrichment.py | Calls OTX API and returns pulse count + raw data |
| `calculate_risk(pulse_count, data)` | enrichment.py | Scores threat level 0–100 from pulse count and malicious tags |
| `threat_check(indicator)` | enrichment.py | Orchestrates: cache check → enrichment → scoring → storage |
| `lookup_indicator(indicator)` | db.py | Checks if indicator exists in local database |
| `store_enrichment(...)` | db.py | Stores enriched results to local database |
| `process_log(filename)` | enrichment.py | Reads input file line by line and runs each indicator through `threat_check` |
| `generate_pdf_report(results)` | report.py | Generates a formatted PDF from processed results |

---

## Threat Scoring

Scores are calculated in `calculate_risk()`:

- **Base score:** `2 × pulse_count`, capped at 70
- **+20 points** if any pulse contains tags: `c2`, `malware`, `ransomware`, `attack`, or `compromise`
- **Final score capped at 100**

| Score | Status | Meaning |
|-------|--------|---------|
| 0 – 19 | `CLEAN` | No significant threat signals |
| 20 – 69 | `SUSPICIOUS` | Some signals present, warrants investigation |
| 70 – 100 | `CRITICAL` | Strong threat signals, treat as malicious |

---

## API Error Handling

All OTX API calls handle the following:

| Status | Behaviour |
|--------|-----------|
| `401` | Invalid API key — prints error and exits immediately |
| `404` | Indicator not found in OTX — soft failure, returns `None` |
| `429` | Rate limited — waits 60 seconds then retries once |
| Timeout | 10 second timeout on all requests — logs warning and returns `None` |
| Other | Unexpected status code — logged and returns `None` |

---

## Input Format

Plain text file with one indicator per line. Type is auto-detected — no manual labeling needed.

```
192.168.1.1
d41d8cd98f00b204e9800998ecf8427e
malicious-domain.com
http://bad-site.com/payload
```

---

## Output

Generates `Threat_Intelligence_Report.pdf` with each indicator's risk score and status label.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `requests` | HTTP calls to OTX API |
| `fpdf` | PDF report generation |
| `ipaddress` | IPv4 validation (built-in) |
| `json` | API response parsing (built-in) |
| `time` | Rate limit sleep handler (built-in) |

---

## Current Limitations

- Only IPv4 enrichment is fully wired up — Domain, URL, and Hash routing is in progress
- PDF report shows basic info — richer tag and pulse detail coming
- Single API source (OTX only) — VirusTotal integration planned
- Command line only — no GUI yet

---

## Planned Features

-  Full multi-indicator routing (Domain, URL, Hash)
-  VirusTotal as a second enrichment source
-  Richer PDF report with tag details and pulse breakdown
-  MITRE ATT&CK tag mapping
-  Email / Slack alerting on CRITICAL indicators
-  Scheduled automated runs

---

*Built as a SOC automation project — actively in development.*
