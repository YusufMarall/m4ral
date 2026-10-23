"""IOC doğrulama ve tür tespiti (PRD 7.3 adım 1-2)."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

from models import IOCInput, IOCType


class IOCValidationError(ValueError):
    """Geçersiz veya desteklenmeyen IOC girdisi."""


_HEX_LENGTHS = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

#: Basitleştirilmiş ancak pratikte yeterli domain doğrulaması.
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)"
    r"(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)
_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")

#: Savunmasızlaştırılmış (defanged) girdileri geri dönüştürmek için kullanılır.
_REFANG_PATTERNS = (
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\s+\.\s*|\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\[:\]|\(:\)|\[colon\]", re.IGNORECASE), ":"),
    (re.compile(r"hxx+ps?", re.IGNORECASE), "http"),
    (re.compile(r"h\[tt\]p", re.IGNORECASE), "http"),
    (re.compile(r"\[@\]|\(@\)", re.IGNORECASE), "@"),
    (re.compile(r"\[//\]|\(//\)", re.IGNORECASE), "//"),
)

#: IOC çıkarımı için metin içi desenler (serbest metin analizinde kullanılır).
_TEXT_URL_RE = re.compile(r"\b(?:https?|hxxps?|h\[tt\]p)://[^\s<>\"')]+", re.IGNORECASE)
_TEXT_IPV4_RE = re.compile(r"\b(?:\d{1,3}(?:\[?\.\]?|\.)){3}\d{1,3}\b")
_TEXT_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_TEXT_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[?\.\]?|\.))+"
    r"(?:com|net|org|io|tr|ru|cn|info|biz|xyz|top|shop|site|online|club|onion|edu|gov)\b",
    re.IGNORECASE,
)


def refang(value: str) -> str:
    """`185[.]220[.]101[.]5` gibi savunmasızlaştırılmış girdiyi geri dönüştürür."""
    result = unicodedata.normalize("NFKC", value).strip()
    for pattern, replacement in _REFANG_PATTERNS:
        result = pattern.sub(replacement, result)
    return result.strip().strip(".,;\"'")


def _is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _is_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def _is_domain(value: str) -> bool:
    if not _DOMAIN_RE.match(value):
        return False
    # Son etiket tamamen sayısal olamaz (aksi halde IP ile karışır).
    tld = value.rsplit(".", 1)[-1]
    return not tld.isdigit()


def _is_url(value: str) -> bool:
    if "://" not in value:
        return False
    parts = urlsplit(value)
    if parts.scheme.lower() not in ("http", "https"):
        return False
    host = parts.hostname
    if not host:
        return False
    return _is_ipv4(host) or _is_ipv6(host) or _is_domain(host)


def detect_ioc_type(value: str) -> IOCType | None:
    """Girdinin türünü belirler. Desteklenmiyorsa `None` döndürür."""
    candidate = refang(value)
    if not candidate:
        return None
    if _is_url(candidate):
        return IOCType.URL
    if _is_ipv4(candidate):
        return IOCType.IPV4
    if _is_ipv6(candidate):
        return IOCType.IPV6
    if _HEX_RE.match(candidate) and len(candidate) in _HEX_LENGTHS:
        return _HEX_LENGTHS[len(candidate)]
    if _is_domain(candidate.lower()):
        return IOCType.DOMAIN
    return None


def normalize_ioc_value(value: str, ioc_type: IOCType) -> str:
    """Türe göre kanonik gösterimi üretir (tekilleştirme için gereklidir)."""
    candidate = refang(value)
    if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        return candidate.lower()
    if ioc_type == IOCType.DOMAIN:
        return candidate.lower().rstrip(".")
    if ioc_type == IOCType.URL:
        parts = urlsplit(candidate)
        scheme = parts.scheme.lower()
        netloc = parts.netloc.lower()
        path = parts.path or "/"
        rebuilt = f"{scheme}://{netloc}{path}"
        if parts.query:
            rebuilt += f"?{parts.query}"
        return rebuilt
    if ioc_type == IOCType.IPV6:
        try:
            return str(ipaddress.IPv6Address(candidate))
        except ValueError:
            return candidate.lower()
    return candidate


def validate_ioc(value: str, declared_type: IOCType | None = None) -> IOCInput:
    """Girdiyi doğrular ve kanonik bir `IOCInput` döndürür.

    Beyan edilen tür ile tespit edilen tür çelişirse `IOCValidationError` yükseltilir.
    """
    if value is None or not str(value).strip():
        raise IOCValidationError("IOC değeri boş olamaz")

    candidate = refang(str(value))
    detected = detect_ioc_type(candidate)
    if detected is None:
        raise IOCValidationError(
            f"Desteklenmeyen IOC formatı: '{value}'. "
            "Desteklenen türler: IPv4, IPv6, domain, URL, MD5, SHA-1, SHA-256."
        )

    if declared_type is not None and IOCType(declared_type) != detected:
        raise IOCValidationError(
            f"Beyan edilen tür ({declared_type}) ile tespit edilen tür ({detected}) uyuşmuyor."
        )

    return IOCInput(value=normalize_ioc_value(candidate, detected), ioc_type=detected)


def extract_indicators(text: str) -> list[tuple[str, IOCType]]:
    """Serbest metinden IOC adaylarını çıkarır.

    Kaynak içerikleri güvenilmeyen veridir; bu fonksiyon yalnızca desen eşleştirir,
    hiçbir bağlantıyı açmaz veya çalıştırmaz (PRD 9.6).
    """
    found: dict[tuple[str, IOCType], None] = {}
    if not text:
        return []

    for candidate in _TEXT_URL_RE.findall(text):
        ioc_type = detect_ioc_type(candidate)
        if ioc_type:
            found[(normalize_ioc_value(candidate, ioc_type), ioc_type)] = None

    for candidate in _TEXT_IPV4_RE.findall(text):
        ioc_type = detect_ioc_type(candidate)
        if ioc_type:
            found[(normalize_ioc_value(candidate, ioc_type), ioc_type)] = None

    for candidate in _TEXT_HASH_RE.findall(text):
        ioc_type = detect_ioc_type(candidate)
        if ioc_type:
            found[(normalize_ioc_value(candidate, ioc_type), ioc_type)] = None

    for candidate in _TEXT_DOMAIN_RE.findall(text):
        ioc_type = detect_ioc_type(candidate)
        if ioc_type:
            found[(normalize_ioc_value(candidate, ioc_type), ioc_type)] = None

    return list(found.keys())


def is_valid_asset_value(asset_type: str, value: str) -> bool:
    """Kurum profili varlıklarının temel doğrulaması."""
    if not value or not value.strip():
        return False
    if asset_type in ("domain", "email_domain", "brand", "keyword", "legal_id", "alias"):
        return len(value.strip()) >= 2
    return detect_ioc_type(value) is not None
