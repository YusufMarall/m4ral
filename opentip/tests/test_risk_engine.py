"""Risk değerlendirmesi ve doğrulama durumu geçiş testleri (PRD 11, 8.5).

PRD Bölüm 11'e göre **risk seviyesi** ile **doğrulama durumu** kesin olarak ayrı
tutulur. Bu testler iki kavramın birbirini otomatik olarak yükseltmediğini
doğrular.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from core.risk_engine import RiskEngine
from models import (
    Finding,
    FindingType,
    IOCRecord,
    IOCSourceResult,
    IOCType,
    RiskLevel,
    SourceStatus,
    VerificationStatus,
    can_transition,
    utcnow,
)


def _ioc(
    *,
    ioc_type: IOCType = IOCType.DOMAIN,
    risk: RiskLevel = RiskLevel.HIGH,
    confidence: float = 0.8,
    source: str = "otx",
    last_seen=None,
) -> IOCRecord:
    return IOCRecord(
        value="evil.example",
        ioc_type=ioc_type,
        source_name=source,
        risk_level=risk,
        confidence=confidence,
        last_seen=last_seen or utcnow(),
    )


def _finding(**kwargs) -> Finding:
    base = {
        "finding_id": "F-TEST",
        "finding_type": FindingType.BREACH_CLAIM,
        "source_name": "provider",
        "organization": "Nesil Teknoloji",
    }
    base.update(kwargs)
    return Finding(**base)


def _factor(assessment, name: str):
    return next(factor for factor in assessment.factors if factor.name == name)


# --------------------------------------------------------------------------- #
# IOC risk değerlendirmesi
# --------------------------------------------------------------------------- #
def test_assess_ioc_without_records_is_unassessed() -> None:
    assessment = RiskEngine().assess_ioc(IOCType.DOMAIN, [])

    assert assessment.level == RiskLevel.UNASSESSED
    assert assessment.score == 0.0
    assert assessment.factors == []
    # Eşleşme yokluğu "temiz" anlamına gelmez; bu not korunmalıdır.
    assert any("temiz olduğu anlamına gelmez" in note for note in assessment.verification_notes)


def test_assess_ioc_single_source_high_risk() -> None:
    assessment = RiskEngine().assess_ioc(
        IOCType.SHA256, [_ioc(risk=RiskLevel.HIGH, confidence=0.8)]
    )

    # 40*0.8 (kanıt) + 20*0.35 (tek kaynak) + 15 (hash türü) + 15 (güncel) + 10*0.5
    assert assessment.score == pytest.approx(74.0, abs=0.1)
    assert assessment.level == RiskLevel.HIGH
    assert any("Tek kaynak" in note for note in assessment.verification_notes)


def test_assess_ioc_corroboration_increases_score_and_removes_note() -> None:
    assessment = RiskEngine().assess_ioc(
        IOCType.DOMAIN, [_ioc(source="otx"), _ioc(source="misp")]
    )

    assert _factor(assessment, "bagimsiz_destek").points == pytest.approx(14.0)  # 20*0.7
    assert not any("Tek kaynak" in note for note in assessment.verification_notes)


def test_assess_ioc_reports_failed_sources_separately() -> None:
    failed = IOCSourceResult(source_name="misp", status=SourceStatus.ERROR, error="timeout")
    assessment = RiskEngine().assess_ioc(IOCType.DOMAIN, [_ioc()], [failed])

    assert any("yanıt vermedi" in note for note in assessment.verification_notes)


def test_assess_ioc_clamps_reliability_and_penalizes_stale_records() -> None:
    engine = RiskEngine()
    stale = utcnow() - timedelta(days=200)

    clamped = engine.assess_ioc(IOCType.DOMAIN, [_ioc()], source_reliability=5.0)
    assert _factor(clamped, "kaynak_guvenilirligi").points == pytest.approx(10.0)

    old = engine.assess_ioc(IOCType.DOMAIN, [_ioc(last_seen=stale)])
    assert _factor(old, "guncellik").points == pytest.approx(3.75)  # 15*0.25


# --------------------------------------------------------------------------- #
# Sızıntı bulgusu risk değerlendirmesi
# --------------------------------------------------------------------------- #
def test_assess_finding_verified_multi_source_is_critical() -> None:
    finding = _finding(claimed_data_types=["credentials"], source_reliability=0.9)

    assessment = RiskEngine().assess_finding(
        finding, evidence_count=3, independent_sources=3, association_verified=True
    )

    # 25 (hassasiyet) + 25 (destek) + 20 (ilişkilendirme) + 15 (kanıt) + 13.5 (güvenilirlik)
    assert assessment.score == pytest.approx(98.5, abs=0.1)
    assert assessment.level == RiskLevel.CRITICAL
    assert assessment.verification_notes == []


def test_assess_finding_single_unverified_source_stays_medium() -> None:
    finding = _finding(claimed_data_types=["credentials"])

    assessment = RiskEngine().assess_finding(
        finding, evidence_count=0, independent_sources=1, association_verified=False
    )

    # 25 + 5 + 8 + 0 + 7.5
    assert assessment.score == pytest.approx(45.5, abs=0.1)
    assert assessment.level == RiskLevel.MEDIUM
    assert any("Tek kaynaklı" in note for note in assessment.verification_notes)
    assert any("İlişkilendirme doğrulanmış" in note for note in assessment.verification_notes)


def test_assess_finding_unknown_data_type_uses_low_default() -> None:
    finding = _finding(claimed_data_types=[])

    assessment = RiskEngine().assess_finding(
        finding, evidence_count=0, independent_sources=1, association_verified=False
    )

    assert _factor(assessment, "veri_hassasiyeti").points == pytest.approx(7.5)  # 25*0.3


def test_risk_assessment_does_not_touch_verification_status() -> None:
    """Risk motoru bulgunun doğrulama durumunu değiştirmemelidir (PRD 11)."""
    finding = _finding(claimed_data_types=["credentials"], source_reliability=0.9)

    RiskEngine().assess_finding(
        finding, evidence_count=3, independent_sources=3, association_verified=True
    )

    assert finding.verification_status == VerificationStatus.NEW
    assert finding.risk_level == RiskLevel.UNASSESSED


# --------------------------------------------------------------------------- #
# Doğrulama durumu geçişleri (PRD 8.5, 8.6)
# --------------------------------------------------------------------------- #
def test_can_transition_allows_review_flow() -> None:
    assert can_transition(VerificationStatus.NEW, VerificationStatus.UNDER_REVIEW)
    assert can_transition(VerificationStatus.UNDER_REVIEW, VerificationStatus.CORROBORATED)
    assert can_transition(VerificationStatus.CORROBORATED, VerificationStatus.CONFIRMED)
    assert can_transition(VerificationStatus.NEW, VerificationStatus.UNVERIFIED_CLAIM)
    assert can_transition(VerificationStatus.NEW, VerificationStatus.NEW)


def test_can_transition_blocks_claim_to_confirmed_without_review() -> None:
    """Tek başına forum iddiası doğrudan `confirmed` olamaz (PRD 8.5)."""
    assert not can_transition(VerificationStatus.NEW, VerificationStatus.CONFIRMED)
    assert not can_transition(VerificationStatus.UNVERIFIED_CLAIM, VerificationStatus.CONFIRMED)
    assert not can_transition(VerificationStatus.CLOSED, VerificationStatus.CONFIRMED)
    assert can_transition(VerificationStatus.CLOSED, VerificationStatus.UNDER_REVIEW)
