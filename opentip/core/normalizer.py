"""Kaynak yanıtlarını ortak veri modeline dönüştürme katmanı (PRD 6, 7.3).

Tüm adaptörler kendi normalize işlemini bu yardımcılarla yapar. Dış kaynaklardan
gelen içerik güvenilmeyen veri olarak ele alınır.
"""

from __future__ import annotations

import hashlib
import html
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from models import IOCRecord, IOCType, RiskLevel, SourceType, utcnow
from .ioc_validator import extract_indicators, normalize_ioc_value

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

#: Risk seviyesi anahtar kelime eşlemesi (kaynak beyanı -> ortak model).
_RISK_KEYWORDS: dict[RiskLevel, tuple[str, ...]] = {
    RiskLevel.CRITICAL: ("critical", "kritik", "severe", "ransomware", "fidye", "apt"),
    RiskLevel.HIGH: ("high", "yüksek", "malicious", "zararlı", "exploit", "trojan", "stealer"),
    RiskLevel.MEDIUM: ("medium", "orta", "suspicious", "şüpheli", "spam", "phishing", "oltalama"),
    RiskLevel.LOW: ("low", "düşük", "benign", "unknown", "informational"),
}


def to_utc(value: datetime) -> datetime:
    """Naive zaman damgalarını UTC olarak işaretler."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Farklı kaynak formatlarındaki zaman damgalarını UTC'ye dönüştürür."""
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, datetime):
        return to_utc(value)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00").replace(" UTC", "+00:00")
    for parser in (
        lambda t: datetime.fromisoformat(t),
        lambda t: datetime.strptime(t, "%Y-%m-%d %H:%M:%S"),
        lambda t: datetime.strptime(t, "%Y-%m-%d %H:%M:%S.%f"),
        lambda t: datetime.strptime(t, "%Y-%m-%dT%H:%M:%S"),
        lambda t: datetime.strptime(t, "%Y-%m-%d"),
        lambda t: datetime.strptime(t, "%d.%m.%Y"),
    ):
        try:
            return to_utc(parser(normalized))
        except ValueError:
            continue
    return None


def normalize_tags(tags: Iterable[Any]) -> list[str]:
    """Etiketleri temizler, küçük harfe indirir ve tekilleştirir."""
    result: list[str] = []
    seen: set[str] = set()
    for tag in tags or []:
        if tag is None:
            continue
        cleaned = _WS_RE.sub(" ", str(tag).strip().lower())
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def coerce_risk_level(value: Any, default: RiskLevel = RiskLevel.UNASSESSED) -> RiskLevel:
    """Kaynağın bildirdiği risk/tehdit bilgisini ortak seviyeye dönüştürür."""
    if value is None:
        return default
    if isinstance(value, RiskLevel):
        return value
    if isinstance(value, (int, float)):
        # OTX pulse ve bazı kaynaklar 0-10 arası sayısal değer kullanır.
        numeric = float(value)
        if numeric >= 8:
            return RiskLevel.CRITICAL
        if numeric >= 6:
            return RiskLevel.HIGH
        if numeric >= 3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
    text = str(value).strip().lower()
    for level, keywords in _RISK_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            return level
    return default


def sanitize_text(value: Any, max_length: int = 600) -> str:
    """Güvenilmeyen metni güvenli, kısa bir özete indirger.

    HTML etiketleri kaldırılır, boşluklar sadeleştirilir ve uzunluk sınırlanır.
    İçerik hiçbir zaman çalıştırılmaz veya otomatik açılmaz (PRD 9.6, 16).
    """
    if value is None:
        return ""
    text = html.unescape(str(value))
    text = _HTML_TAG_RE.sub(" ", text)
    text = _WS_RE.sub(" ", text).strip()
    if len(text) > max_length:
        text = text[: max_length - 1].rstrip() + "…"
    return text


def content_digest(value: Any) -> str:
    """Kanıt gövdesinin sha256 özetini üretir (gövde saklanmaz, yalnızca referans tutulur)."""
    payload = str(value).encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


def build_ioc_record(
    *,
    value: str,
    ioc_type: IOCType,
    source_name: str,
    source_type: SourceType = SourceType.IOC_FEED,
    source_reference: Optional[str] = None,
    first_seen: Any = None,
    last_seen: Any = None,
    tags: Optional[Iterable[Any]] = None,
    risk_level: Any = None,
    confidence: Optional[float] = None,
    detail: Optional[dict[str, Any]] = None,
) -> IOCRecord:
    """Kaynak verisinden tek bir ortak IOC kaydı üretir."""
    canonical = normalize_ioc_value(value, ioc_type)
    now = utcnow()
    return IOCRecord(
        value=canonical,
        ioc_type=ioc_type,
        source_name=source_name,
        source_type=source_type,
        source_reference=source_reference,
        first_seen=parse_timestamp(first_seen) or now,
        last_seen=parse_timestamp(last_seen) or now,
        tags=normalize_tags(tags or []),
        risk_level=coerce_risk_level(risk_level),
        confidence=confidence,
        detail=detail or {},
    )


def records_from_text(
    text: str,
    *,
    source_name: str,
    source_type: SourceType,
    source_reference: Optional[str] = None,
    tags: Optional[Iterable[Any]] = None,
    detail: Optional[dict[str, Any]] = None,
) -> list[IOCRecord]:
    """Serbest metinden IOC kayıtları çıkarır (Breach/Dark Web içerikleri için)."""
    records = []
    for value, ioc_type in extract_indicators(text or ""):
        records.append(
            build_ioc_record(
                value=value,
                ioc_type=ioc_type,
                source_name=source_name,
                source_type=source_type,
                source_reference=source_reference,
                tags=tags,
                detail=detail,
            )
        )
    return records


def is_fresh(last_seen: Optional[datetime], max_age_days: int = 90) -> bool:
    """Kaydın güncelliğini değerlendirir (risk motoru kullanır)."""
    if last_seen is None:
        return False
    return to_utc(last_seen) >= utcnow() - timedelta(days=max_age_days)
