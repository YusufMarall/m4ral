"""IOC doğrulama, tür tespiti ve metinden gösterge çıkarma testleri (PRD 7.3)."""

from __future__ import annotations

import pytest

from core.ioc_validator import (
    IOCValidationError,
    detect_ioc_type,
    extract_indicators,
    is_valid_asset_value,
    normalize_ioc_value,
    refang,
    validate_ioc,
)
from models import IOCType


# --------------------------------------------------------------------------- #
# Tür tespiti
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value,expected",
    [
        ("8.8.8.8", IOCType.IPV4),
        ("185[.]220[.]101[.]5", IOCType.IPV4),
        ("2001:db8::1", IOCType.IPV6),
        ("example.com", IOCType.DOMAIN),
        ("Example.COM.", IOCType.DOMAIN),
        ("https://example.com/login", IOCType.URL),
        ("hxxps://evil[.]com/payload", IOCType.URL),
        ("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCType.SHA1),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            IOCType.SHA256,
        ),
    ],
)
def test_detect_ioc_type(value: str, expected: IOCType) -> None:
    assert detect_ioc_type(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "   ", "not-an-ioc", "999.999.999.999", "ftp://example.com", "hello world"],
)
def test_detect_ioc_type_unsupported(value: str) -> None:
    assert detect_ioc_type(value) is None


# --------------------------------------------------------------------------- #
# Savunmasızlaştırılmış (defanged) girdilerin geri dönüştürülmesi
# --------------------------------------------------------------------------- #
def test_refang_variants() -> None:
    assert refang("hxxp://evil[.]com") == "http://evil.com"
    assert refang("185[.]220[.]101[.]5") == "185.220.101.5"
    assert refang("user[@]example[.]com") == "user@example.com"
    assert refang("bad[dot]example[dot]com") == "bad.example.com"


# --------------------------------------------------------------------------- #
# Kanonik gösterim ve doğrulama
# --------------------------------------------------------------------------- #
def test_validate_ioc_normalizes_domain() -> None:
    parsed = validate_ioc("  Example.COM.  ")
    assert parsed.ioc_type == IOCType.DOMAIN
    assert parsed.value == "example.com"


def test_validate_ioc_normalizes_url() -> None:
    parsed = validate_ioc("HTTPS://Example.com/Path?q=1")
    assert parsed.ioc_type == IOCType.URL
    assert parsed.value == "https://example.com/Path?q=1"


def test_validate_ioc_hash_lowercased() -> None:
    parsed = validate_ioc("D41D8CD98F00B204E9800998ECF8427E")
    assert parsed.ioc_type == IOCType.MD5
    assert parsed.value == "d41d8cd98f00b204e9800998ecf8427e"


def test_normalize_ioc_value_ipv6() -> None:
    assert normalize_ioc_value("2001:0db8:0000:0000:0000:0000:0000:0001", IOCType.IPV6) == "2001:db8::1"


def test_validate_ioc_type_conflict_raises() -> None:
    with pytest.raises(IOCValidationError):
        validate_ioc("example.com", declared_type=IOCType.IPV4)


@pytest.mark.parametrize("value", ["", "   ", "!!gecersiz!!"])
def test_validate_ioc_rejects_invalid(value: str) -> None:
    with pytest.raises(IOCValidationError):
        validate_ioc(value)


# --------------------------------------------------------------------------- #
# Serbest metinden gösterge çıkarma
# --------------------------------------------------------------------------- #
def test_extract_indicators_from_untrusted_text() -> None:
    text = (
        "C2 sunucusu 185.220.101.5 adresinde çalışıyor, "
        "indirme bağlantısı hxxps://bad[.]example[.]com/malware.bin ve "
        "örnek hash d41d8cd98f00b204e9800998ecf8427e"
    )
    found = {value: ioc_type for value, ioc_type in extract_indicators(text)}

    assert found["185.220.101.5"] == IOCType.IPV4
    assert found["d41d8cd98f00b204e9800998ecf8427e"] == IOCType.MD5
    assert IOCType.URL in found.values()


def test_extract_indicators_empty_text() -> None:
    assert extract_indicators("") == []


# --------------------------------------------------------------------------- #
# Kurum varlık doğrulaması
# --------------------------------------------------------------------------- #
def test_is_valid_asset_value() -> None:
    assert is_valid_asset_value("domain", "example.com")
    assert is_valid_asset_value("brand", "Nesil")
    assert is_valid_asset_value("ip", "8.8.8.8")
    assert not is_valid_asset_value("domain", "  ")
    assert not is_valid_asset_value("ip", "not-an-ip")
