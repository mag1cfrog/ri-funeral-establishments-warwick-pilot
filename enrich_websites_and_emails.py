import re, logging, urllib.parse, time, os
from typing import Dict, Optional, List

from bs4 import BeautifulSoup, Comment
from email_validator import validate_email, EmailNotValidError
import tldextract
import httpx
import pandas as pd
from tenacity import retry, stop_after_attempt, wait_exponential_jitter, before_sleep_log

from logutil import setup_logger
import settings

PLACES_URL = "https://places.googleapis.com/v1/places:searchText"
API_KEY = settings.GOOGLE_MAPS_API_KEY
log = setup_logger("ri.enrich", settings.LOG_LEVEL)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)

def _tobool(v) -> bool:
    return str(v).strip().lower() in {"1","true","yes","y","on"}

DNS_CHECK = _tobool(getattr(settings, "EMAIL_DNS_CHECK", os.getenv("EMAIL_DNS_CHECK", "0")))

def _brandish(a: str, b: str) -> bool:
    def clean(s): return re.sub(r"[^a-z]", "", s.lower())
    # drop common industry stopwords
    drop = ("the","funeral","home","homes","fh","mortuary","memorial","services","service")
    ca = clean(a)
    cb = clean(b)
    for w in drop:
        ca = ca.replace(w, "")
        cb = cb.replace(w, "")
    return bool(ca) and bool(cb) and (ca in cb or cb in ca)

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

def _origin(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    return f"{u.scheme}://{u.netloc}" if u.scheme and u.netloc else url

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

def _same_registrable(a: str, b: str) -> bool:
    if not a or not b: return False
    ea, eb = tldextract.extract(a), tldextract.extract(b)
    da = f"{ea.domain}.{ea.suffix}" if ea.suffix else ea.domain
    db = f"{eb.domain}.{eb.suffix}" if eb.suffix else eb.domain
    return bool(da) and bool(db) and da.lower() == db.lower()

def _validate_and_rank(emails: list[str], website: str|None) -> list[str]:
    host = (urllib.parse.urlsplit(website).hostname or "").lower() if website else ""
    ranked = []
    for e in sorted(set(emails)):
        try:
            info = validate_email(e, check_deliverability=DNS_CHECK)  # MX/A check
            norm = info.normalized
            domain = norm.split("@", 1)[1].lower()
            score = 0
            if host and _same_registrable(host, domain):
                score -= 10
            elif host and _brandish(host, domain):
                score -= 4
            if domain in {"gmail.com","outlook.com","hotmail.com","yahoo.com"}: score += 2
            ranked.append((score, norm))
        except EmailNotValidError:
            log.debug(f"[EMAIL] invalid: {e}")
    ranked.sort()
    return [e for _, e in ranked]

def extract_emails_from_html(html: str, website: str|None = None) -> list[str]:
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    # strip non-visible / noisy nodes
    for tag in soup(["script","style","noscript","svg","link","meta","iframe"]):
        tag.decompose()
    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        c.extract()

    # 1) mailto: first
    emails = set()
    for a in soup.select('a[href^="mailto:"]'):
        raw_href = a.get("href")
        if isinstance(raw_href, list):
            raw_href = raw_href[0] if raw_href else ""
        href = str(raw_href or "")
        # Defensive: ensure mailto scheme and robust splitting even if malformed
        if not href.lower().startswith("mailto:"):
            continue
        after_scheme = href.split(":", 1)[1] if ":" in href else href
        local_part = after_scheme.split("?", 1)[0]
        addr = urllib.parse.unquote(local_part).strip()
        if addr:
            emails.add(addr.lower())

    # 2) visible text, with *targeted* de-obfuscation on the text only
    text = soup.get_text(" ", strip=True)
    # replace only tokenized at/dot; then extract
    line = re.sub(r"(?i)(?:\(|\[)?\bat\b(?:\)|\])", "@", text)
    line = re.sub(r"(?i)(?:\(|\[)?\bdot\b(?:\)|\])", ".", line)

    # collapse spaces to form real addresses
    line = re.sub(r"\s*@\s*", "@", line)
    line = re.sub(r"\s*\.\s*", ".", line)
    emails |= {m.group(0).lower() for m in EMAIL_RE.finditer(line)}

    # 3) validate + rank
    return _validate_and_rank(list(emails), website)

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
                found += extract_emails_from_html(html, website=origin)
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
        origin = ""
        email = None
        try:
            resp = places_text_search_get_website(query)
            best = pick_best_candidate(resp, city)
            website_raw = best.get("websiteUri") if best else None
            origin = _origin(website_raw) if website_raw else ""
            email = crawl_for_email(origin) if origin else None
        except Exception as e:
            log.warning(f"[ENRICH] failed for {name!r}: {e}")
            origin, email = "", None

        log.info(f"[RESULT] {name} | website={bool(origin)} | email={bool(email)}")
        rows.append({
            "Business Name": name,
            "Street": str(row.get("License Address Line 1","")).strip(),
            "City": city,
            "State": str(row.get("State","")).strip(),
            "ZIP": str(row.get("Zip","")).strip(),
            "Phone": str(row.get("Phone","")).strip(),
            "Fax": str(row.get("Fax","")).strip(),
            "Owner / Manager": str(row.get("Owner Manager Name","")).strip(),
            "Status": str(row.get("Status","")).strip(),
            "Issue Date": str(row.get("Issue Date","")).strip(),
            "Expiration Date": str(row.get("Expiration Date","")).strip(),
            "Website URL": origin or "",
            "General Email": email or "",
            "Source": "RI DOH list + business website"
        })
    return pd.DataFrame(rows)