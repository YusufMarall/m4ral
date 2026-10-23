"""OpenTIP ortak numaralandırmaları.

Tüm modüller (IOC, Breach, Dark Web) aynı durum ve seviye sözlüğünü kullanır.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """JSON'a doğrudan serileştirilebilen string enum."""

    def __str__(self) -> str:  # pragma: no cover - kolaylık
        return self.value


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class SourceType(StrEnum):
    IOC_FEED = "ioc_feed"
    BREACH_FEED = "breach_feed"
    DARKWEB_SOURCE = "darkweb_source"


class SourceCategory(StrEnum):
    """PRD Bölüm 9.2 kaynak kategorileri."""

    STRUCTURED_API = "structured_api"       # Kategori 1
    AUTHORIZED_WEB = "authorized_web"       # Kategori 2
    COMMERCIAL_PROVIDER = "commercial"      # Kategori 3
    MANUAL = "manual"                       # Kategori 4


class SourceStatus(StrEnum):
    OK = "ok"
    ERROR = "error"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class RunStatus(StrEnum):
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class FindingType(StrEnum):
    IOC_MATCH = "ioc_match"
    BREACH_CLAIM = "breach_claim"
    DARKWEB_RECORD = "darkweb_record"


class VerificationStatus(StrEnum):
    """PRD Bölüm 8.5 doğrulama durumları."""

    NEW = "new"
    UNDER_REVIEW = "under_review"
    UNVERIFIED_CLAIM = "unverified_claim"
    CORROBORATED = "corroborated"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class RiskLevel(StrEnum):
    """PRD Bölüm 11: risk seviyesi doğrulama durumundan bağımsızdır."""

    UNASSESSED = "unassessed"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CatalogNetwork(StrEnum):
    """Katalog kaydının yayınlandığı ağ (deepdarkCTI harmanlaması)."""

    TOR = "tor"
    CLEARNET = "clearnet"
    UNKNOWN = "unknown"


class CatalogStatus(StrEnum):
    """Katalog kaydının kaynak tarafından beyan edilen erişilebilirlik durumu."""

    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class ChangeType(StrEnum):
    """PRD Bölüm 9.5 değişiklik tespiti sonuçları."""

    NEW = "new"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    MISSING = "missing"          # Kaynakta artık erişilemeyen / silinmiş kayıt
    UNCHECKED = "unchecked"      # Kaynak hatası nedeniyle kontrol edilemedi


#: Doğrulama durumu geçişleri. PRD Bölüm 8.5 ve 8.6 ile uyumludur.
VERIFICATION_TRANSITIONS: dict[VerificationStatus, set[VerificationStatus]] = {
    VerificationStatus.NEW: {
        VerificationStatus.UNDER_REVIEW,
        VerificationStatus.UNVERIFIED_CLAIM,
        VerificationStatus.FALSE_POSITIVE,
        VerificationStatus.CLOSED,
    },
    VerificationStatus.UNDER_REVIEW: {
        VerificationStatus.UNVERIFIED_CLAIM,
        VerificationStatus.CORROBORATED,
        VerificationStatus.CONFIRMED,
        VerificationStatus.FALSE_POSITIVE,
        VerificationStatus.CLOSED,
    },
    VerificationStatus.UNVERIFIED_CLAIM: {
        VerificationStatus.UNDER_REVIEW,
        VerificationStatus.CORROBORATED,
        VerificationStatus.FALSE_POSITIVE,
        VerificationStatus.CLOSED,
    },
    VerificationStatus.CORROBORATED: {
        VerificationStatus.CONFIRMED,
        VerificationStatus.UNDER_REVIEW,
        VerificationStatus.FALSE_POSITIVE,
        VerificationStatus.CLOSED,
    },
    VerificationStatus.CONFIRMED: {
        VerificationStatus.UNDER_REVIEW,
        VerificationStatus.CLOSED,
    },
    VerificationStatus.FALSE_POSITIVE: {
        VerificationStatus.UNDER_REVIEW,
        VerificationStatus.CLOSED,
    },
    VerificationStatus.CLOSED: {
        VerificationStatus.UNDER_REVIEW,
    },
}


def can_transition(current: VerificationStatus, target: VerificationStatus) -> bool:
    """İki doğrulama durumu arasında geçişe izin verilip verilmediğini döndürür."""
    if current == target:
        return True
    return target in VERIFICATION_TRANSITIONS.get(current, set())
