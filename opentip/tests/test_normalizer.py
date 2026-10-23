"""Ortak veri modeline dönüştürme ve bulgu tekilleştirme testleri (PRD 7.3, 9.5).

Kaynak yanıtları güvenilmeyen veri kabul edilir; bu testler normalize katmanının
bu veriyi güvenli, kanonik ve deterministik biçimde ortak modele indirdiğini
doğrular.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.deduplicator import (
    deduplicate_records,
    finding_fingerprint,
    fingerprint,
    ioc_fingerprint,
    merge_source_references,
)
from core.normalizer import (
    build_ioc_record,
    coerce_risk_level,
    content_digest,
    is_fresh,
    normalize_tags,
    parse_timestamp,
    records_from_text,
    sanitize_text,
    to_utc,
)
from models import Finding, FindingType, IOCRecord, IOCType, RiskLevel, SourceType, utcnow


# --------------------------------------------------------------------------- #
# Zaman damgası dönüşümleri
# --------------------------------------------------------------------------- #
def test_to_utc_marks_naive_and_converts_aware() -> None:
    naive = datetime(2024, 1, 1, 12, 0, 0)
    assert to_utc(naive) == datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    aware = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone(timedelta(hours=3)))
    assert to_utc(aware) == datetime(2024, 1, 1, 9, 0, 0, tzinfo=timezone.utc)


def test_parse_timestamp_handles_common_source_formats() -> None:
    expected = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert parse_timestamp("2024-01-02T03:04:05Z") == expected
    assert parse_timestamp("2024-01-02T03:04:05+00:00") == expected
    assert parse_timestamp("2024-01-02 03:04:05") == expected
    assert parse_timestamp("2024-01-02") == datetime(2024, 1, 2, tzinfo=timezone.utc)
    assert parse_timestamp("02.01.2024") == datetime(2024, 1, 2, tzinfo=timezone.utc)
    assert parse_timestamp(1704164645) == datetime.fromtimestamp(1704164645, tz=timezone.utc)


def test_parse_timestamp_returns_none_for_missing_or_invalid() -> None:
    assert parse_timestamp(None) is None
    assert parse_timestamp("") is None
    assert parse_timestamp(0) is None
    assert parse_timestamp("0") is None
    assert parse_timestamp("bilinmeyen-tarih") is None


# --------------------------------------------------------------------------- #
# Etiket ve risk normalizasyonu
# --------------------------------------------------------------------------- #
def test_normalize_tags_lowercases_deduplicates_and_trims() -> None:
    assert normalize_tags([" Zed ", "zed", None, "Alpha  Beta"]) == ["zed", "alpha beta"]
    assert normalize_tags([]) == []


def test_coerce_risk_level_from_text_and_numbers() -> None:
    assert coerce_risk_level(None) == RiskLevel.UNASSESSED
    assert coerce_risk_level(RiskLevel.HIGH) == RiskLevel.HIGH
    assert coerce_risk_level("ransomware aktivitesi") == RiskLevel.CRITICAL
    assert coerce_risk_level("şüpheli trafik") == RiskLevel.MEDIUM
    assert coerce_risk_level(9) == RiskLevel.CRITICAL
    assert coerce_risk_level(6) == RiskLevel.HIGH
    assert coerce_risk_level(3) == RiskLevel.MEDIUM
    assert coerce_risk_level(1) == RiskLevel.LOW
    assert coerce_risk_level("tanımsız-ifade") == RiskLevel.UNASSESSED


# --------------------------------------------------------------------------- #
# Güvenilmeyen metnin güvenli hale getirilmesi
# --------------------------------------------------------------------------- #
def test_sanitize_text_strips_html_and_collapses_whitespace() -> None:
    assert sanitize_text("<b>Tehdit</b>   &amp; risk") == "Tehdit & risk"
    assert sanitize_text("<script>alert(1)</script>") == "alert(1)"
    assert sanitize_text(None) == ""


def test_sanitize_text_truncates_long_content() -> None:
    result = sanitize_text("a" * 50, max_length=5)
    assert result == "aaaa…"
    assert len(result) == 5


def test_content_digest_is_deterministic_sha256() -> None:
    assert content_digest("aynı içerik") == content_digest("aynı içerik")
    assert content_digest("bir") != content_digest("iki")
    assert len(content_digest("kanıt")) == 64


# --------------------------------------------------------------------------- #
# Ortak IOC kaydı üretimi
# --------------------------------------------------------------------------- #
def test_build_ioc_record_normalizes_value_tags_and_risk() -> None:
    record = build_ioc_record(
        value="Example.COM.",
        ioc_type=IOCType.DOMAIN,
        source_name="otx",
        source_reference="otx:pulse:1",
        tags=["Threat", "threat", None],
        risk_level="high",
        confidence=0.8,
    )
    assert record.value == "example.com"
    assert record.tags == ["threat"]
    assert record.risk_level == RiskLevel.HIGH
    assert record.source_reference == "otx:pulse:1"
    assert record.first_seen.tzinfo is not None
    assert record.last_seen.tzinfo is not None


def test_records_from_text_extracts_indicators_with_source_metadata() -> None:
    records = records_from_text(
        "C2 sunucusu 185.220.101.5 adresinde; örnek hash "
        "d41d8cd98f00b204e9800998ecf8427e",
        source_name="provider",
        source_type=SourceType.BREACH_FEED,
    )
    found = {record.value: record.ioc_type for record in records}

    assert found["185.220.101.5"] == IOCType.IPV4
    assert found["d41d8cd98f00b204e9800998ecf8427e"] == IOCType.MD5
    assert all(record.source_type == SourceType.BREACH_FEED for record in records)


def test_is_fresh_uses_max_age() -> None:
    now = utcnow()
    assert is_fresh(now) is True
    assert is_fresh(now - timedelta(days=30)) is True
    assert is_fresh(now - timedelta(days=200)) is False
    assert is_fresh(None) is False


# --------------------------------------------------------------------------- #
# Tekilleştirme
# --------------------------------------------------------------------------- #
def _ioc_record(
    *,
    value: str = "evil.example",
    source: str,
    risk: RiskLevel,
    confidence: float,
    tags: list[str] | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
) -> IOCRecord:
    moment = last_seen or utcnow()
    return IOCRecord(
        value=value,
        ioc_type=IOCType.DOMAIN,
        source_name=source,
        source_reference=f"{source}:1",
        risk_level=risk,
        confidence=confidence,
        tags=tags or [],
        first_seen=first_seen or moment,
        last_seen=moment,
    )


def test_deduplicate_records_merges_sources_but_keeps_highest_risk() -> None:
    early = utcnow() - timedelta(days=10)
    late = utcnow()
    first = _ioc_record(
        source="otx", risk=RiskLevel.MEDIUM, confidence=0.4, tags=["phishing"],
        first_seen=early, last_seen=early,
    )
    second = _ioc_record(
        source="misp", risk=RiskLevel.HIGH, confidence=0.9, tags=["c2"],
        first_seen=late, last_seen=late,
    )

    merged = deduplicate_records([first, second])

    assert len(merged) == 1
    record = merged[0]
    assert record.risk_level == RiskLevel.HIGH
    assert record.confidence == 0.9
    assert record.tags == ["c2", "phishing"]
    assert record.first_seen == early
    assert record.last_seen == late
    assert {entry["source_name"] for entry in record.detail["sources"]} == {"otx", "misp"}


def test_deduplicate_records_keeps_distinct_values_separate() -> None:
    records = [
        _ioc_record(value="a.example", source="otx", risk=RiskLevel.LOW, confidence=0.1),
        _ioc_record(value="b.example", source="otx", risk=RiskLevel.LOW, confidence=0.1),
    ]
    assert len(deduplicate_records(records)) == 2


def test_fingerprint_is_deterministic_and_case_insensitive() -> None:
    assert fingerprint("A ", "b") == fingerprint("a", "B")
    record = _ioc_record(source="otx", risk=RiskLevel.LOW, confidence=0.1)
    assert ioc_fingerprint(record) == ioc_fingerprint(record.model_copy(deep=True))


def test_finding_fingerprint_changes_with_source_reference() -> None:
    base = Finding(
        finding_id="",
        finding_type=FindingType.BREACH_CLAIM,
        organization="Nesil Teknoloji",
        source_name="provider",
        source_reference="ref-1",
    )
    same = base.model_copy(deep=True)
    other = base.model_copy(update={"source_reference": "ref-2"})

    assert finding_fingerprint(base) == finding_fingerprint(same)
    assert finding_fingerprint(base) != finding_fingerprint(other)


def test_merge_source_references_is_lossless() -> None:
    merged = merge_source_references(
        {"sources": [{"source_name": "otx"}]},
        [{"source_name": "otx"}, {"source_name": "misp"}],
    )
    assert merged["sources"] == [{"source_name": "otx"}, {"source_name": "misp"}]
    assert merge_source_references(None, []) == {"sources": []}
