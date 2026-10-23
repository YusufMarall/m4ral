"""Kaynak adaptörleri ve güvenli HTTP katmanı testleri (PRD 7.2, 8.7, 16).

Tüm HTTP etkileşimi sahte oturumlar üzerinden yürütülür; gerçek kaynaklara
erişilmez (PRD 17 "test yaklaşımı").
"""

from __future__ import annotations

import pytest

from adapters.base import (
    AdapterConfigError,
    AdapterError,
    AdapterUnavailable,
    RateLimiter,
    chunked,
)
from adapters.breach_feed import BreachFeedAdapter
from adapters.otx import OTXAdapter
from adapters.threatfox import ThreatFoxAdapter
from adapters.xposedornot import XposedOrNotAdapter
from models import (
    FindingType,
    IOCInput,
    IOCType,
    RiskLevel,
    SourceConfig,
    SourceType,
    VerificationStatus,
)


def _config(
    name: str,
    adapter: str,
    source_type: SourceType = SourceType.IOC_FEED,
    **settings_map,
) -> SourceConfig:
    return SourceConfig(
        name=name,
        adapter=adapter,
        source_type=source_type,
        settings=settings_map,
        check_interval_minutes=30,
    )


# --------------------------------------------------------------------------- #
# AlienVault OTX
# --------------------------------------------------------------------------- #
def test_otx_lookup_maps_pulse_to_shared_record(settings, make_session, make_response) -> None:
    payload = {
        "pulse_info": {
            "count": 2,
            "pulses": [
                {
                    "id": "pulse-1",
                    "name": "Demo Pulse",
                    "adversary": "APT-Demo",
                    "tags": ["phishing"],
                    "malware_families": [{"display_name": "DemoStealer"}],
                    "attack_ids": [{"name": "T1566"}],
                    "threat_level": 2,
                    "created": "2024-01-01T00:00:00",
                    "modified": "2024-02-01T00:00:00",
                }
            ],
        }
    }
    session = make_session([make_response(200, payload=payload)])
    adapter = OTXAdapter(
        _config("otx-test", "otx", url="https://otx.example.com/api/v1"), settings, session=session
    )

    records = adapter.lookup_ioc(IOCInput(value="evil.example", ioc_type=IOCType.DOMAIN))

    assert len(records) == 1
    record = records[0]
    assert record.value == "evil.example"
    assert record.source_reference == "otx:pulse:pulse-1"
    assert record.confidence == pytest.approx(0.2)  # 2 pulse / 10
    assert record.risk_level == RiskLevel.HIGH  # "stealer" anahtar kelimesi
    assert "demostealer" in record.tags
    assert record.detail["pulse_name"] == "Demo Pulse"
    assert session.calls[0]["method"] == "GET"
    assert session.calls[0]["url"].endswith("/indicators/domain/evil.example/general")


def test_otx_lookup_returns_empty_on_not_found(settings, make_session, make_response) -> None:
    session = make_session([make_response(404, payload=None)])
    adapter = OTXAdapter(
        _config("otx-test", "otx", url="https://otx.example.com/api/v1"), settings, session=session
    )

    assert adapter.lookup_ioc(IOCInput(value="evil.example", ioc_type=IOCType.DOMAIN)) == []


def test_otx_rejects_unsupported_ioc_type(settings) -> None:
    adapter = OTXAdapter(_config("otx-test", "otx"), settings, session=None)

    with pytest.raises(AdapterConfigError):
        adapter.lookup_ioc(IOCInput(value="evil.example"))


# --------------------------------------------------------------------------- #
# ThreatFox
# --------------------------------------------------------------------------- #
def test_threatfox_lookup_requires_api_key(settings, make_session) -> None:
    no_key = settings.model_copy(update={"threatfox_api_key": ""})
    adapter = ThreatFoxAdapter(
        _config("tf", "threatfox", api_key_env="THREATFOX_API_KEY"),
        no_key,
        session=make_session([]),
    )

    with pytest.raises(AdapterConfigError):
        adapter.lookup_ioc(IOCInput(value="1.1.1.1", ioc_type=IOCType.IPV4))


def test_threatfox_lookup_parses_entries(settings, make_session, make_response) -> None:
    keyed = settings.model_copy(update={"threatfox_api_key": "test-key"})
    payload = {
        "query_status": "ok",
        "data": [
            {
                "id": "42",
                "ioc": "1.1.1.1:443",
                "threat_type": "botnet_cc",
                "confidence_level": 75,
                "first_seen_utc": "2024-01-01 00:00:00",
                "last_seen_utc": "2024-02-01 00:00:00",
                "tags": ["c2"],
                "malware_printable": "DemoLoader",
                "reporter": "analyst",
            }
        ],
    }
    session = make_session([make_response(200, payload=payload)])
    adapter = ThreatFoxAdapter(
        _config("tf", "threatfox", api_key_env="THREATFOX_API_KEY"), keyed, session=session
    )

    records = adapter.lookup_ioc(IOCInput(value="1.1.1.1", ioc_type=IOCType.IPV4))

    assert len(records) == 1
    record = records[0]
    assert record.source_reference == "threatfox:42"
    assert record.confidence == pytest.approx(0.75)
    assert record.risk_level == RiskLevel.HIGH
    assert "demoloader" in record.tags
    assert session.calls[0]["kwargs"]["json"]["query"] == "search_ioc"
    assert session.calls[0]["kwargs"]["headers"]["Auth-Key"] == "test-key"


def test_threatfox_no_result_returns_empty(settings, make_session, make_response) -> None:
    keyed = settings.model_copy(update={"threatfox_api_key": "test-key"})
    session = make_session([make_response(200, payload={"query_status": "no_result", "data": None})])
    adapter = ThreatFoxAdapter(
        _config("tf", "threatfox", api_key_env="THREATFOX_API_KEY"), keyed, session=session
    )

    assert adapter.lookup_ioc(IOCInput(value="1.1.1.1", ioc_type=IOCType.IPV4)) == []


# --------------------------------------------------------------------------- #
# Yapılandırılmış sızıntı akışı (PRD 8.7)
# --------------------------------------------------------------------------- #
def test_breach_feed_flow_normalizes_record(settings, make_session, make_response) -> None:
    payload = {
        "records": [
            {
                "id": "rec-1",
                "organization": "Nesil Teknoloji",
                "domain": "NesilTeknoloji.COM",
                "summary": (
                    "<b>Forum iddiası</b>: C2 185.220.101.5 ve örnek hash "
                    "d41d8cd98f00b204e9800998ecf8427e"
                ),
                "data_types": ["passwords", "emails"],
                "claimed_date": "2026-01-01",
                "reference": "https://provider.example/record/1",
                "confidence": 0.7,
                "verified": False,
            }
        ]
    }
    session = make_session([make_response(200, payload=payload)])
    adapter = BreachFeedAdapter(
        _config(
            "provider",
            "breach_feed",
            SourceType.BREACH_FEED,
            url="https://provider.example/api/records",
        ),
        settings,
        session=session,
    )

    raw = adapter.fetch_updates()
    assert len(raw) == 1

    finding = adapter.normalize_record(raw[0])

    assert finding.finding_type == FindingType.BREACH_CLAIM
    assert finding.matched_domain == "nesilteknoloji.com"
    assert finding.claimed_data_types == ["credentials", "contact"]
    # Sağlayıcı doğrulamadıysa iddia doğrulanmamış kabul edilir (PRD 8.5).
    assert finding.verification_status == VerificationStatus.UNVERIFIED_CLAIM
    assert "<b>" not in finding.evidence_summary
    assert finding.source_reliability == pytest.approx(0.7)
    assert "185.220.101.5" in finding.metadata["indicators"]
    assert finding.metadata["untrusted_source"] is True


# --------------------------------------------------------------------------- #
# XposedOrNot
# --------------------------------------------------------------------------- #
def test_xposedornot_lookup_domain_parses_public_breaches(settings, make_session, make_response) -> None:
    payload = {
        "status": "success",
        "exposedBreaches": [
            {
                "breachID": "DemoLeak",
                "breachedDate": "2024-05-01T00:00:00+00:00",
                "domain": "example.com",
                "industry": "government",
                "passwordRisk": "plaintext",
                "sensitive": True,
                "verified": True,
                "exposedData": ["Email addresses", "Passwords"],
                "exposedRecords": 5000,
                "exposureDescription": "Demo breach details",
                "referenceURL": "https://xposedornot.example/breach/DemoLeak",
            }
        ],
    }
    session = make_session([make_response(200, payload=payload)])
    adapter = XposedOrNotAdapter(_config("xon", "xposedornot"), settings, session=session)

    records = adapter.lookup_ioc(IOCInput(value="example.com", ioc_type=IOCType.DOMAIN))

    assert len(records) == 1
    record = records[0]
    assert record.value == "example.com"
    assert record.source_reference == "https://xposedornot.example/breach/DemoLeak"
    assert record.risk_level == RiskLevel.CRITICAL
    assert "demoleak" in record.tags
    assert "government" in record.tags
    assert session.calls[0]["kwargs"]["params"]["domain"] == "example.com"


def test_xposedornot_lookup_returns_empty_on_not_found(settings, make_session, make_response) -> None:
    session = make_session([make_response(404, payload=None)])
    adapter = XposedOrNotAdapter(_config("xon", "xposedornot"), settings, session=session)

    assert adapter.lookup_ioc(IOCInput(value="example.com", ioc_type=IOCType.DOMAIN)) == []


def test_xposedornot_fetch_updates_requires_api_key(settings, make_session) -> None:
    adapter = XposedOrNotAdapter(_config("xon", "xposedornot"), settings, session=make_session([]))

    with pytest.raises(AdapterConfigError):
        adapter.fetch_updates()


def test_xposedornot_fetch_updates_and_normalize(settings, make_session, make_response) -> None:
    keyed = settings.model_copy(update={"xposedornot_api_key": "xon-key"})
    payload = {
        "status": "success",
        "metrics": {
            "Breaches_Details": [
                {"email": "user@example.com", "domain": "example.com", "breach": "DemoLeak"}
            ],
            "Detailed_Breach_Info": {
                "DemoLeak": {
                    "breachedDate": "2024-05-01T00:00:00+00:00",
                    "exposureDescription": "<b>Passwords</b> and email addresses exposed.",
                    "exposedData": ["Passwords", "Email addresses"],
                    "verified": True,
                    "referenceURL": "https://xposedornot.example/breach/DemoLeak",
                }
            },
        },
    }
    session = make_session([make_response(200, payload=payload)])
    adapter = XposedOrNotAdapter(
        _config("xon", "xposedornot", SourceType.BREACH_FEED, api_key_env="XPOSEDORNOT_API_KEY"),
        keyed,
        session=session,
    )

    raw = adapter.fetch_updates()
    assert len(raw) == 1

    finding = adapter.normalize_record(raw[0])
    assert finding.finding_type == FindingType.BREACH_CLAIM
    assert finding.matched_domain == "example.com"
    assert finding.claimed_data_types == ["credentials", "contact"]
    assert finding.verification_status == VerificationStatus.CORROBORATED
    assert "<b>" not in finding.evidence_summary
    assert finding.source_reference == "https://xposedornot.example/breach/DemoLeak"


# --------------------------------------------------------------------------- #
# Güvenli HTTP katmanı (PRD 16)
# --------------------------------------------------------------------------- #
def test_validate_url_blocks_private_and_invalid_targets() -> None:
    for url in (
        "http://127.0.0.1/x",
        "http://localhost/x",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5/api",
        "ftp://example.com/file",
    ):
        with pytest.raises(AdapterConfigError):
            OTXAdapter._validate_url(url)

    # Genel bir HTTPS adresi kabul edilir.
    OTXAdapter._validate_url("https://otx.alienvault.com/api/v1")


def test_request_retries_transient_error_then_succeeds(
    settings, make_session, make_response
) -> None:
    session = make_session(
        [make_response(500, payload=None), make_response(200, payload={"ok": True})]
    )
    adapter = OTXAdapter(
        _config("otx-test", "otx", url="https://otx.example.com/api/v1"), settings, session=session
    )

    assert adapter.check_connection() is True
    assert len(session.calls) == 2


def test_request_raises_on_authorization_error(settings, make_session, make_response) -> None:
    session = make_session([make_response(401, payload=None)])
    adapter = OTXAdapter(
        _config("otx-test", "otx", url="https://otx.example.com/api/v1"), settings, session=session
    )

    with pytest.raises(AdapterError):
        adapter.request("GET", "https://otx.example.com/api/v1/x")


def test_request_raises_unavailable_after_exhausting_retries(settings, make_session) -> None:
    session = make_session([OSError("ağ yok")] * 4)
    adapter = OTXAdapter(
        _config("otx-test", "otx", url="https://otx.example.com/api/v1"), settings, session=session
    )

    with pytest.raises(AdapterUnavailable):
        adapter.request("GET", "https://otx.example.com/api/v1/x")
    assert len(session.calls) == 4  # ilk deneme + 3 tekrar


def test_chunked_and_rate_limiter_helpers() -> None:
    assert chunked([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]

    limiter = RateLimiter(per_minute=100)
    limiter.acquire()  # hemen döner
    assert limiter.per_minute == 100
