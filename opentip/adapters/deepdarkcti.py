"""deepdarkCTI kaynak kataloğu için salt-okunur HTTP istemcisi.

Bu adaptör **bulgu üretmez**. Görevi, deepdarkCTI deposundaki kategori
markdown dosyalarını güvenli biçimde indirmek ve ham metni döndürmektir.
Ayrıştırma ve kayıt işlemleri `core.deepdark` içindeki katalog servisinde yapılır.

Yalnızca yapılandırmada tanımlı taban adresten (varsayılan: projenin resmî
GitHub ham içerik adresi) tek bir dosya istenir; herhangi bir bağlantı takip
edilmez, dönen içerik hiçbir zaman çalıştırılmaz (PRD 9.6).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

from models import SourceCategory, SourceConfig, SourceType

from .base import (
    CAP_CONNECTION_CHECK,
    AdapterConfigError,
    AdapterUnavailable,
    BaseAdapter,
)

DEEPDARK_CATALOG_NAME = "deepdarkcti"
#: deepdarkCTI deposunun ham içerik adresi (GPL-3.0, küratörlü kaynak listesi).
DEEPDARK_DEFAULT_BASE_URL = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/"

#: Yalnızca depo kökündeki düz dosya adlarına izin verilir (yol gezinmesi engeli).
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class DeepDarkCTIAdapter(BaseAdapter):
    """deepdarkCTI markdown dosyalarını indirir."""

    adapter_name = DEEPDARK_CATALOG_NAME
    source_type = SourceType.DARKWEB_SOURCE
    default_category = SourceCategory.MANUAL
    capabilities = {CAP_CONNECTION_CHECK}
    requires_api_key = False
    required_settings = ("base_url",)

    # ------------------------------------------------------------------ #
    @property
    def base_url(self) -> str:
        """Sonunda eğik çizgi olan taban adres."""
        return self.require_config("base_url").rstrip("/") + "/"

    def fetch_markdown(self, path: str) -> str:
        """Depodaki tek bir markdown dosyasını ham metin olarak döndürür."""
        if not _SAFE_PATH_RE.match(path or ""):
            raise AdapterConfigError(
                f"{self.name}: geçersiz dosya adı '{path}'. Yalnızca depo kökündeki "
                "düz dosya adları indirilebilir."
            )
        url = urljoin(self.base_url, path)
        response = self.request(
            "GET",
            url,
            headers={"Accept": "text/plain, text/markdown;q=0.9"},
            retries=2,
            allow_redirects=False,
        )
        if getattr(response, "status_code", 0) == 404:
            raise AdapterUnavailable(f"{self.name}: '{path}' bulunamadı (HTTP 404).")
        text = getattr(response, "text", "") or ""
        if not text.strip():
            raise AdapterUnavailable(f"{self.name}: '{path}' boş yanıt döndü.")
        return text

    def check_connection(self) -> bool:
        """Katalog deposuna erişimin doğrulanması (README dosyası ile)."""
        try:
            text = self.fetch_markdown("README.md")
            ok = bool(text.strip())
            self.record_run(success=ok, message="" if ok else "Depo yanıtı boş")
            return ok
        except Exception as exc:
            self.record_run(success=False, message=str(exc))
            return False


def build_deepdarkcti_adapter(settings: Any) -> DeepDarkCTIAdapter:
    """`.env` ayarlarından katalog istemcisini üretir."""
    config = SourceConfig(
        name=DEEPDARK_CATALOG_NAME,
        adapter=DEEPDARK_CATALOG_NAME,
        source_type=SourceType.DARKWEB_SOURCE,
        category=SourceCategory.MANUAL,
        enabled=bool(getattr(settings, "deepdarkcti_enabled", True)),
        check_interval_minutes=1440,
        reliability=0.7,
        settings={
            "base_url": getattr(settings, "deepdarkcti_base_url", None)
            or DEEPDARK_DEFAULT_BASE_URL
        },
        notes=(
            "deepdarkCTI küratörlü kaynak kataloğu (GitHub, GPL-3.0). "
            "Katalog referans verisidir; tek başına bulgu üretmez."
        ),
    )
    return DeepDarkCTIAdapter(config, settings)


__all__ = [
    "DeepDarkCTIAdapter",
    "DEEPDARK_DEFAULT_BASE_URL",
    "DEEPDARK_CATALOG_NAME",
    "build_deepdarkcti_adapter",
]
