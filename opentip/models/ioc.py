"""IOC (Indicator of Compromise) veri modelleri."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from .enums import IOCType, RiskLevel, SourceStatus, SourceType


def utcnow() -> datetime:
    """Saat dilimi bilinçli UTC zaman damgası üretir."""
    return datetime.now(timezone.utc)


class IOCInput(BaseModel):
    """Kullanıcıdan alınan ham IOC girdisi."""

    model_config = ConfigDict(str_strip_whitespace=True)

    value: str = Field(..., min_length=1, description="Ham gösterge değeri")
    ioc_type: Optional[IOCType] = Field(
        default=None,
        description="Beyan edilen tür. Boşsa sistem otomatik tespit eder.",
    )


class IOCRecord(BaseModel):
    """Bir kaynaktan dönen tek bir IOC kaydı (ortak veri modeli)."""

    model_config = ConfigDict(use_enum_values=False)

    value: str
    ioc_type: IOCType
    source_name: str
    source_type: SourceType = SourceType.IOC_FEED
    source_reference: Optional[str] = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    tags: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.UNASSESSED
    confidence: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Kaynağın bildirdiği güven (0-1)"
    )
    #: Kaynak yanıtından saklanan asgari metadata. Ham yanıtın tamamı saklanmaz.
    detail: dict[str, Any] = Field(default_factory=dict)
    #: Tekilleştirme için kullanılan parmak izi (core.deduplicator tarafından üretilir).
    fingerprint: Optional[str] = None


class IOCSourceResult(BaseModel):
    """Tek bir kaynağın IOC sorgusu sonucu.

    Kaynak hatası ile "eşleşme yok" durumu kesin olarak ayrılır (PRD 7.3, 19.3).
    """

    source_name: str
    source_type: SourceType = SourceType.IOC_FEED
    status: SourceStatus = SourceStatus.UNKNOWN
    records: list[IOCRecord] = Field(default_factory=list)
    error: Optional[str] = None
    checked_at: datetime = Field(default_factory=utcnow)
    duration_ms: Optional[int] = None

    @property
    def has_error(self) -> bool:
        return self.status in (SourceStatus.ERROR, SourceStatus.UNAVAILABLE)

    @property
    def matched(self) -> bool:
        return self.status == SourceStatus.OK and len(self.records) > 0


class AnalysisResult(BaseModel):
    """Bir IOC için tüm kaynakların birleşik analiz sonucu."""

    value: str
    ioc_type: IOCType
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None
    source_results: list[IOCSourceResult] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.UNASSESSED
    risk_reasons: list[str] = Field(default_factory=list)
    risk_score: Optional[float] = None
    #: Tekilleştirme sonrası benzersiz IOC kayıtları
    deduplicated_records: list[IOCRecord] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def failed_sources(self) -> list[str]:
        return [r.source_name for r in self.source_results if r.has_error]

    @property
    def queried_sources(self) -> list[str]:
        return [r.source_name for r in self.source_results]
