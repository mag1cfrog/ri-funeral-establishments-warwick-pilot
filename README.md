# RI Funeral Establishments - Warwick Pilot

A small, end-to-end pilot that:

1) downloads the Rhode Island Department of Health "Licensee Lists" CSV for **Embalming/Funeral Directing - Funeral Establishment**, and  
2) enriches the rows by finding the business website and a general contact email (when available).

The pilot is intentionally scoped to **Warwick, RI** to keep iterations fast and safe. It's easy to adapt to other cities once the workflow feels solid.

---

## What this does (at a glance)

- **Automates the DOH form** with Playwright (Python) to download the official CSV.
- **Looks up each business** with Google Places Text Search to get a website URL candidate.
- **Crawls the site politely** (home, /contact, /about, etc.), honoring `robots.txt`, and extracts **mailto:** links and lightly-obfuscated addresses in visible text.
- **Validates emails** (syntax + optional DNS/MX) and picks a "likely general" mailbox (`info@`, `office@`, `contact@`, etc.).
- **Writes a tidy CSV** with original DOH fields plus `Website URL` and `General Email`.
- **Logs verbosely** so you can see what happened for each record.

> Sources: the DOH list, the business's public website, and the Google Places API for discovery. See **Compliance & Ethics** below.

---

## Repository layout

```
.
├─ download_ri_csv.py          # Playwright automation for DOH Licensee Lists
├─ enrich_websites_and_emails.py  # Places lookup + polite crawl + email extraction
├─ run_pilot.py                # Orchestrates the pilot end-to-end
├─ settings.py                 # Centralized config (LOG_LEVEL, API key, flags)
├─ logutil.py                  # Logging helper
├─ tests/                      # Pytest suite (incl. Hypothesis fuzzing)
└─ data/
   ├─ raw/                     # Downloaded CSV from DOH
   └─ processed/               # Enriched CSV output
```

---

## Requirements

- **Python 3.11+**
- Either **[uv](https://github.com/astral-sh/uv)** or **pip + venv**
- **Playwright (Python)** and the Chromium browser
- A **Google Places API key** with access to the Places Text Search API

---

## Setup

### 1) Create and activate a virtual environment

With **uv** (recommended for speed):

```bash
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt
```

Or with **pip**:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Install Playwright browsers

```bash
python -m playwright install chromium
```

### 3) Configure environment

Create a `.env` (or set real env vars) and add at least:

```bash
GOOGLE_MAPS_API_KEY=your_api_key_here
# Optional toggles
LOG_LEVEL=INFO             # DEBUG for very chatty logs
EMAIL_DNS_CHECK=0          # 1 to enable MX/A DNS checks (slower, more precise)
```

`settings.py` reads from env and provides sane defaults.

---

## Running the pilot

### Download the DOH CSV

```bash
uv run download_ri_csv.py
# writes: data/raw/ri_ef_funeral_establishments.csv
```

### Enrich with websites & emails

```bash
uv run run_pilot.py
# reads:  data/raw/ri_ef_funeral_establishments.csv
# writes: data/processed/warwick_funeral_homes.csv
```

You'll see logs like:

```
[PLACES] query='BARRETTAND COTTER FUNERAL HOME WARWICK RI funeral home'
[WEBURL] raw='https://example.com/contact?utm_source=google...' clean='https://example.com/contact' canonical=None used='https://example.com/contact'
[CRAWL] fetch https://example.com/contact -> ok
[CRAWL] emails on https://example.com/contact: ['info@example.com']
[RESULT] ... | website=True | email=True
```

---

## Configuration notes

- **Website URL selection**: we take the Places `websiteUri` (when available), strip tracking params, optionally honor a page's `<link rel="canonical">`, and use that as the **stored Website URL** and the **crawl start URL**.
- **Crawl scope**: same-origin only, a handful of likely pages (`/`, `/contact`, `/about`, `/locations`, etc.). Obeys `robots.txt`. Conservative page cap to stay polite.
- **Email extraction**: pulls from `mailto:` and visible text; de-obfuscates variants like `name (at) example (dot) com`. We ignore `<script>`/`<style>`/hidden nodes and validate results.
- **Ranking**: prefer the business's own domain (or close brand match), then generic mailboxes (`info@`, `office@`, `contact@`, …). Free webmail domains are de-prioritized.
- **Logging**: set `LOG_LEVEL=DEBUG` for per-page crawl traces and candidate lists.

---

## Testing

```bash
uv run pytest -q
```

- Property-based tests (Hypothesis) fuzz obfuscated email text.
- Monkeypatched tests simulate Places responses and HTML fetches.
- Edge cases covered: JSON-LD emails, non-HTML responses, robots-respect, canonical URLs, DNS validation toggles.

---

## Compliance & ethics

- **robots.txt**: The crawler checks and respects each site's robots policy and keeps the request volume small.
- **Google Places**: The project uses Places Text Search to *discover* a business website and then crawls that public site directly.

The goal is to use **minimally necessary** data, be a **good web citizen**, and provide a transparent audit trail via logs.

---

## Data provenance

- **Licenses**: Rhode Island Department of Health "Licensee Lists" page.
- **Websites + emails**: the businesses' own public websites, discovered via Places.
- The enriched CSV includes a `Source` column and **only** retains what we derive from public pages.

---
