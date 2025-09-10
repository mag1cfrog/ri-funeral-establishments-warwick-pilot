import pandas as pd
import enrich_website_and_emails as mod

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