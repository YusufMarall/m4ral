"""Kaynak yapılandırması, çalışma kaydı ve sağlık durumu modelleri."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from .enums import (
    RunStatus,
    SourceCategory,
    SourceStatus,
    SourceType,
)
from .ioc import utcnow


class SourceConfig(BaseModel):
    """Bir veri kaynağının veritabanındaki yapılandırması.

    Kaynak kimlik bilgileri burada saklanmaz; yalnızca hangi ortam
    değişkeninin kullanılacağına dair anahtar adı tutulur (PRD 16).
    """

    source_id: Optional[int] = None
    name: str
    adapter: str
    source_type: SourceType
    category: SourceCategory = SourceCategory.STRUCTURED_API
    enabled: bool = True
    check_interval_minutes: int = 60
    #: Kaynak güvenilirliği (0-1). Risk motoru bu değeri kullanır.
    reliability: float = Field(default=0.5, ge=0.0, le=1.0)
    #: Kaynağa özel ayarlar (örn. {"url": "...", "api_key_env": "OTX_API_KEY"}).
    settings: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""


class SourceRun(BaseModel):
    """Bir kaynağın tek bir kontrol çalışması (PRD 9.4)."""

    run_id: Optional[int] = None
    source_id: Optional[int] = None
    source_name: str
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None
    status: RunStatus = RunStatus.RUNNING
    records_fetched: int = 0
    findings_created: int = 0
    findings_updated: int = 0
    error_message: Optional[str] = None
    triggered_by: str = "manual"

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()


class SourceHealth(BaseModel):
    """Kaynağın güncel çalışma durumu.

    Kaynak yanıt vermediğinde son başarılı kontrol zamanı korunur (PRD 9.4).
    """

    source_name: str
    source_id: Optional[int] = None
    status: SourceStatus = SourceStatus.UNKNOWN
    message: str = ""
    last_checked_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    last_error_at: Optional[datetime] = None
    consecutive_failures: int = 0
    check_interval_minutes: int = 60
    enabled: bool = True
