"""Bulgu, kanıt, alarm ve analist notu modelleri.

`Finding` modeli PRD Bölüm 10'daki ortak JSON yapısıyla birebir uyumludur.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from .enums import FindingType, RiskLevel, SourceType, VerificationStatus
from .ioc import IOCType, utcnow


class Evidence(BaseModel):
    """Bir bulguyu destekleyen kaynak referansı ve kanıt özeti.

    Sızdırılmış hassas verinin kendisi saklanmaz; yalnızca güvenli referans
    ve kısa özet tutulur (PRD 8.4, 16).
    """

    evidence_id: Optional[int] = None
    finding_id: Optional[str] = None
    source_name: str
    source_type: SourceType = SourceType.BREACH_FEED
    source_reference: Optional[str] = None
    collected_at: datetime = Field(default_factory=utcnow)
    summary: str = ""
    content_type: str = "text/plain"
    #: Kanıt gövdesinin sha256 özeti (bütünlük referansı; gövde saklanmaz).
    content_digest: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class AnalystNote(BaseModel):
    """Analistin bulguya bağlı serbest notu."""

    note_id: Optional[int] = None
    finding_id: str
    author: str = "analyst"
    note: str
    created_at: datetime = Field(default_factory=utcnow)


class Alert(BaseModel):
    """Uygulama içi alarm (PRD Bölüm 12)."""

    alert_id: Optional[int] = None
    alert_type: str
    severity: RiskLevel = RiskLevel.UNASSESSED
    finding_id: Optional[str] = None
    source_name: Optional[str] = None
    title: str = ""
    message: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    acknowledged: bool = False


class Finding(BaseModel):
    """IOC eşleşmesi, sızıntı iddiası veya Dark Web kaydı için ortak bulgu modeli."""

    model_config = ConfigDict(use_enum_values=False)

    #: PRD Bölüm 10 örnek yapısı ile uyumlu alanlar
    finding_id: str
    finding_type: FindingType
    organization: Optional[str] = None
    matched_domain: Optional[str] = None
    source_type: SourceType = SourceType.IOC_FEED
    source_name: str
    source_reference: Optional[str] = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_checked: datetime = Field(default_factory=utcnow)
    verification_status: VerificationStatus = VerificationStatus.NEW
    risk_level: RiskLevel = RiskLevel.UNASSESSED
    evidence_summary: str = ""
    notifications_sent: bool = False

    #: Ek alanlar
    organization_id: Optional[int] = None
    ioc_value: Optional[str] = None
    ioc_type: Optional[IOCType] = None
    claimed_event_date: Optional[datetime] = None
    claimed_data_types: list[str] = Field(default_factory=list)
    source_reliability: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    risk_score: Optional[float] = None
    risk_reasons: list[str] = Field(default_factory=list)
    #: Tekilleştirme parmak izi; aynı iddianın tekrar tespitini engeller.
    fingerprint: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_public_dict(self) -> dict[str, Any]:
        """PRD Bölüm 10'daki örnek JSON yapısını döndürür."""
        return {
            "finding_id": self.finding_id,
            "finding_type": str(self.finding_type),
            "organization": self.organization,
            "matched_domain": self.matched_domain,
            "source_type": str(self.source_type),
            "source_name": self.source_name,
            "source_reference": self.source_reference,
            "first_seen": self.first_seen.isoformat(),
            "last_checked": self.last_checked.isoformat(),
            "verification_status": str(self.verification_status),
            "risk_level": str(self.risk_level),
            "evidence_summary": self.evidence_summary,
            "notifications_sent": self.notifications_sent,
        }
