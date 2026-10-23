"""Değişiklik tespiti testleri (PRD 9.5).

Aynı kaydın tekrar alınması yeni alarm üretmemelidir; yalnızca yeni veya önemli
ölçüde değişmiş kayıtlar işlem gerektirir.
"""

from __future__ import annotations

from core.deduplicator import finding_fingerprint
from monitoring.change_detector import ChangeDetector
from models import (
    ChangeType,
    Finding,
    FindingType,
    RiskLevel,
    SourceType,
    VerificationStatus,
)


def _finding(
    reference: str,
    *,
    source: str = "fake",
    risk: RiskLevel = RiskLevel.LOW,
    summary: str = "Sağlayıcı kaydı",
    data_types: list[str] | None = None,
    verification: VerificationStatus = VerificationStatus.NEW,
) -> Finding:
    finding = Finding(
        finding_id="",
        finding_type=FindingType.BREACH_CLAIM,
        source_type=SourceType.BREACH_FEED,
        source_name=source,
        source_reference=reference,
        risk_level=risk,
        evidence_summary=summary,
        claimed_data_types=list(data_types or []),
        verification_status=verification,
    )
    finding.fingerprint = finding_fingerprint(finding)
    return finding


def _store(repos, finding: Finding) -> Finding:
    """Bilinen kaydı veritabanına yazar (önceki kontrolü taklit eder)."""
    finding.finding_id = f"F-{finding.source_reference}"
    saved, created, _ = repos.findings.upsert(finding)
    assert created is True
    return saved


def test_classify_new_record(repos) -> None:
    detector = ChangeDetector(repos)
    incoming = [_finding("ref-1")]

    summary, to_save = detector.classify("fake", incoming)

    assert summary.totals["new"] == 1
    assert summary.new[0].change_type == ChangeType.NEW
    assert to_save == incoming
    assert summary.actionable == summary.new + summary.updated


def test_classify_repeated_record_is_unchanged(repos) -> None:
    detector = ChangeDetector(repos)
    _store(repos, _finding("ref-1"))

    summary, to_save = detector.classify("fake", [_finding("ref-1")])

    assert summary.totals == {"new": 0, "updated": 0, "unchanged": 1, "missing": 0, "unchecked": 0}
    assert to_save == []


def test_classify_changed_risk_is_updated_and_reuses_finding_id(repos) -> None:
    detector = ChangeDetector(repos)
    existing = _store(repos, _finding("ref-1", risk=RiskLevel.LOW))
    incoming = _finding("ref-1", risk=RiskLevel.CRITICAL)

    summary, to_save = detector.classify("fake", [incoming])

    assert summary.totals["updated"] == 1
    assert "risk_level" in summary.updated[0].changed_fields
    assert to_save == [incoming]
    assert incoming.finding_id == existing.finding_id


def test_classify_missing_record(repos) -> None:
    detector = ChangeDetector(repos)
    _store(repos, _finding("ref-1"))
    _store(repos, _finding("ref-2"))

    summary, to_save = detector.classify("fake", [_finding("ref-1")])

    assert summary.totals["missing"] == 1
    assert summary.missing[0].source_reference == "ref-2"
    assert to_save == []


def test_classify_source_error_marks_known_records_unchecked(repos) -> None:
    detector = ChangeDetector(repos)
    _store(repos, _finding("ref-1"))
    _store(repos, _finding("ref-2"))

    summary, to_save = detector.classify("fake", [], source_ok=False)

    assert summary.totals["unchecked"] == 2
    assert summary.unchecked[0].change_type == ChangeType.UNCHECKED
    assert to_save == []


def test_classify_applies_default_finding_type_when_no_records(repos) -> None:
    """Kaynak hatasında karşılaştırma türü adaptörden alınır."""
    detector = ChangeDetector(repos)
    _store(repos, _finding("ref-1"))

    summary, _ = detector.classify(
        "fake", [], source_ok=False, finding_type=FindingType.BREACH_CLAIM
    )
    assert summary.totals["unchecked"] == 1

    other = ChangeDetector(repos).classify(
        "fake", [], source_ok=False, finding_type=FindingType.DARKWEB_RECORD
    )[0]
    assert other.totals["unchecked"] == 0
