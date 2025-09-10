import re, logging, urllib.parse, time
from typing import Dict, Optional, List

import httpx
import pandas as pd
from tenacity import retry, stop_after_attempt, wait_exponential_jitter, before_sleep_log

from logutil import setup_logger
import settings

PLACES_URL = "https://places.googleapis.com/v1/places:searchText"
API_KEY = settings.GOOGLE_MAPS_API_KEY
log = setup_logger("ri.enrich", settings.LOG_LEVEL)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)

# ---- HTTPX client with event hooks for terse request/response logs
def _mk_client() -> httpx.Client:
    def log_req(request: httpx.Request):
        log.debug(f"REQ {request.method} {request.url}")

    def log_resp(response: httpx.Response):
        log.debug(f"RES {response.request.method} {response.request.url} -> {response.status_code}")

    return httpx.Client(
        timeout=20,
        follow_redirects=True,
        event_hooks={"request": [log_req], "response": [log_resp]},  # :contentReference[oaicite:12]{index=12}
        headers={"User-Agent": "ri-pilot/1.0 (+compliance; email-extract)"},
    )

_client = _mk_client()

@retry(stop=stop_after_attempt(3),
    wait=wait_exponential_jitter(1, 3),
    before_sleep=before_sleep_log(logging.getLogger("ri.enrich.retry"), logging.WARNING)
)
def places_text_search_get_website(query: str) -> Dict:
    headers = {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": API_KEY,
        "X-Goog-FieldMask": "places.id,places.displayName,places.formattedAddress,places.googleMapsUri,places.websiteUri",
    }
    payload = {
        "textQuery": query,
        "includedType": "funeral_home",
        "strictTypeFiltering": True,
        "maxResultCount": 5
    }
    log.info(f"[PLACES] query={query!r}")
    r = _client.post(PLACES_URL, headers=headers, json=payload)
    r.raise_for_status()
    return r.json()

def pick_best_candidate(resp: Dict, expected_city: str) -> Optional[Dict]:
    places = resp.get("places", [])
    if not places:
        return None
    ec = (expected_city or "").lower()
    places.sort(key=lambda p: (ec not in p.get("formattedAddress", "").lower()))
    best = places[0]
    log.info(f"[PLACES] best={best.get('displayName',{}).get('text','')} @ {best.get('formattedAddress','')}")
    return best

def robots_allows(url: str, path: str) -> bool:
    from urllib.robotparser import RobotFileParser
    base = urllib.parse.urlsplit(url)
    robots = f"{base.scheme}://{base.netloc}/robots.txt"
    rp = RobotFileParser()
    try:
        rp.set_url(robots); rp.read()
        allowed = rp.can_fetch("*", f"{base.scheme}://{base.netloc}{path}")
        log.debug(f"[ROBOTS] {robots} path={path} allowed={allowed}")
        return allowed
    except Exception as e:
        log.warning(f"[ROBOTS] unreachable: {robots} ({e}); default allow")
        return True
    
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential_jitter(1, 3),
    before_sleep=before_sleep_log(logging.getLogger("ri.enrich.retry"), logging.WARNING)
)
def fetch(url: str) -> Optional[str]:
    r = _client.get(url)
    if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
        return r.text
    log.debug(f"[FETCH] skip non-HTML/status: {r.status_code} {url}")
    return None

def extract_emails_from_html(html: str) -> List[str]:
    emails = set(m.group(0).lower() for m in EMAIL_RE.finditer(html or ""))
    html2 = html.replace("[at]", "@").replace("(at)", "@").replace(" at ", "@").replace(" dot ", ".")
    emails |= set(m.group(0).lower() for m in EMAIL_RE.finditer(html2))
    return sorted(emails)

def crawl_for_email(website: str) -> Optional[str]:
    if not website:
        return None
    if not website.startswith("http"):
        website = "https://" + website.lstrip("/")
    origin = "{u.scheme}://{u.netloc}".format(u=urllib.parse.urlsplit(website))
    candidates = ["/", "/contact", "/contact-us", "/about", "/about-us"]
    found: list[str] = []
    for path in candidates:
        if robots_allows(origin, path):
            html = fetch(origin + path)
            if html:
                found += extract_emails_from_html(html)
        time.sleep(0.6)  # polite
    if not found:
        log.info(f"[EMAIL] none found for {origin}")
        return None
    def generic_first(e: str) -> tuple[int, str]:
        return (0 if re.match(r"^(info|office|admin|contact|service|support)@", e) else 1, e)
    found_sorted = sorted(set(found), key=generic_first)
    if log.level <= logging.DEBUG:
        log.debug(f"[EMAIL] candidates={found_sorted}")
    return found_sorted[0]

def enrich(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in df.iterrows():
        name = str(row["Name"]).strip()
        city = str(row.get("City","")).strip()
        query = f"{name} {city} RI funeral home"
        try:
            resp = places_text_search_get_website(query)
            best = pick_best_candidate(resp, city)
            website = best.get("websiteUri") if best else None  # use for navigation only
            email = crawl_for_email(website) if website else None
        except Exception as e:
            log.warning(f"[ENRICH] failed for {name!r}: {e}")
            website, email = None, None

        log.info(f"[RESULT] {name} | website={bool(website)} | email={bool(email)}")
        rows.append({
            "Business Name": name,
            "Street": str(row.get("License Address Line 1","")).strip(),
            "City": city,
            "State": str(row.get("State","")).strip(),
            "ZIP": str(row.get("Zip","")).strip(),
            "Website URL": website or "",
            "General Email": email or "",
            "Source": "RI DOH list + business website"
        })
    return pd.DataFrame(rows)