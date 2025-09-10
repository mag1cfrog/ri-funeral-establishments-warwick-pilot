import re

import pandas as pd

import enrich_websites_and_emails as mod

def test_extract_emails_from_html_variants():
    html = """
        Contact: info@example.com
        Obfuscated: sales (at) example dot org
        Another: ADMIN@Example.COM
    """
    emails = mod.extract_emails_from_html(html)
    assert "info@example.com" in emails
    assert "sales@example.org" in emails
    assert "admin@example.com" in emails

def test_pick_best_candidate_city_bias():
    resp = {
        "places": [
            {"formattedAddress": "123 Elsewhere, OTHER CITY, RI", "displayName": {"text": "A"}},
            {"formattedAddress": "55 Match St, Providence, RI", "displayName": {"text": "B"}},
        ]
    }
    best = mod.pick_best_candidate(resp, "Providence")
    assert best is not None
    assert best["displayName"]["text"] == "B"

def test_enrich_monkeypatched(monkeypatch):
    def fake_places(q):
        return {"places": [{"websiteUri": "https://example.com"}]}
    def fake_crawl(url):
        return "info@example.com"

    monkeypatch.setattr(mod, "places_text_search_get_website", fake_places)
    monkeypatch.setattr(mod, "crawl_for_email", fake_crawl)

    df = pd.DataFrame([{
        "Name": "Sample Funeral Home",
        "License Address Line 1": "1 Main St",
        "City": "Providence",
        "State": "RI",
        "Zip": "02901"
    }])
    out = mod.enrich(df)
    row = out.iloc[0]
    assert row["Website URL"] == "https://example.com"
    assert row["General Email"] == "info@example.com"

def test_enrich_handles_failure(monkeypatch):
    def boom(q):
        raise RuntimeError("api down")
    monkeypatch.setattr(mod, "places_text_search_get_website", boom)
    monkeypatch.setattr(mod, "crawl_for_email", lambda *_: None)

    df = pd.DataFrame([{
        "Name": "Fail Case",
        "License Address Line 1": "X",
        "City": "Nowhere",
        "State": "RI",
        "Zip": "00000"
    }])
    out = mod.enrich(df)
    row = out.iloc[0]
    assert row["Website URL"] == ""
    assert row["General Email"] == ""

def test_crawl_normalizes_url_scheme(monkeypatch):
    import enrich_websites_and_emails as mod
    calls = []
    monkeypatch.setattr(mod, "robots_allows", lambda *_: True)
    def fake_fetch(url):
        calls.append(url)
        return "<a href='mailto:info@example.com'>Email</a>"
    monkeypatch.setattr(mod, "fetch", fake_fetch)
    email = mod.crawl_for_email("example.com")
    assert email == "info@example.com"
    assert any(u.startswith("https://example.com") for u in calls)

def test_crawl_respects_robots(monkeypatch):
    import enrich_websites_and_emails as mod
    monkeypatch.setattr(mod, "robots_allows", lambda *_: False)
    monkeypatch.setattr(mod, "fetch", lambda *_: (_ for _ in ()).throw(AssertionError("should not fetch")))
    assert mod.crawl_for_email("https://example.com") is None

def test_fetch_non_html(monkeypatch):
    import enrich_websites_and_emails as mod
    class R:
        status_code = 200
        headers = {"content-type":"application/pdf"}
        text = "%PDF-1.7..."
        @property
        def request(self): 
            class Req: method="GET"; url="https://e.com/file.pdf"
            return Req()
    monkeypatch.setattr(mod, "_client", type("C", (), {"get": lambda *_: R()})())
    assert mod.fetch("https://e.com/file.pdf") is None

def test_generic_email_preferred():
    import enrich_websites_and_emails as mod
    html = "Contact admin@ex.com or director@ex.com or info@ex.com"
    emails = mod.extract_emails_from_html(html)
    # We only test ordering when crawl_for_email sorts — emulate that logic:
    preferred = sorted(set(emails), key=lambda e: (0 if re.match(r"^(info|office|admin|contact|service|support)@", e) else 1, e))[0]
    assert preferred in ("admin@ex.com","info@ex.com","contact@ex.com")

def test_pick_best_handles_missing_address():
    import enrich_websites_and_emails as mod
    resp = {"places":[{"displayName":{"text":"X"}}, {"formattedAddress":"123 Warwick, RI","displayName":{"text":"Y"}}]}
    best = mod.pick_best_candidate(resp, "Warwick")
    assert best is not None
    assert best["displayName"]["text"] == "Y"

def test_pick_best_empty():
    import enrich_websites_and_emails as mod
    assert mod.pick_best_candidate({"places":[]}, "Warwick") is None

from pandas.testing import assert_frame_equal

def test_enrich_schema_and_blanks(monkeypatch):
    import enrich_websites_and_emails as mod
    monkeypatch.setattr(mod, "places_text_search_get_website", lambda q: {"places":[]})
    df = pd.DataFrame([{"Name":"A","License Address Line 1":"X","City":"Warwick","State":"RI","Zip":"02886"}])
    out = mod.enrich(df)
    assert list(out.columns) == ["Business Name","Street","City","State","ZIP","Website URL","General Email","Source"]
    assert out.iloc[0]["Website URL"] == ""
    assert out.iloc[0]["General Email"] == ""

from hypothesis import given, strategies as st

@given(
    user=st.from_regex(r"[a-z]{3,10}", fullmatch=True),
    host=st.from_regex(r"[a-z]{3,10}", fullmatch=True),
    tld=st.sampled_from(["com","org","net"])
)
def test_obfuscation_fuzz(user, host, tld):
    base = f"{user}@{host}.{tld}"
    variants = [
        f"{user} (at) {host} dot {tld}",
        f"{user} [AT] {host} [DOT] {tld}",
        f"{user} at {host} (dot) {tld}",
    ]
    for v in variants:
        emails = mod.extract_emails_from_html(v)
        assert base in emails