"""Kaynak adaptörleri için ortak temel sınıf (PRD 9.3).

Her izleme kaynağı bu arayüzü uygular. Adaptörler yalnızca gerçekten
destekledikleri yetenekleri (`capabilities`) beyan eder; desteklenmeyen
işlevler varmış gibi gösterilmez.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Optional, Sequence
from urllib.parse import urlsplit

from models import (
    IOCInput,
    IOCRecord,
    SourceCategory,
    SourceConfig,
    SourceHealth,
    SourceStatus,
    SourceType,
    utcnow,
)

#: Adaptör yetenek adları
CAP_IOC_LOOKUP = "ioc_lookup"
CAP_FETCH_UPDATES = "fetch_updates"
CAP_CONNECTION_CHECK = "connection_check"


class AdapterError(Exception):
    """Adaptör kaynaklı hata. `status` alanı kaynak durumunu belirtir."""

    def __init__(self, message: str, status: SourceStatus = SourceStatus.ERROR) -> None:
        super().__init__(message)
        self.status = status


class AdapterUnavailable(AdapterError):
    """Kaynak erişilemez durumda (ağ hatası, 5xx, zaman aşımı)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status=SourceStatus.UNAVAILABLE)


class AdapterConfigError(AdapterError):
    """Kaynak yapılandırması eksik veya geçersiz."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status=SourceStatus.ERROR)


class AdapterNotSupported(AdapterError):
    """Adaptörün desteklemediği işlem çağrıldı."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status=SourceStatus.ERROR)


class RateLimiter:
    """Basit, iş parçacığı güvenli istek hızı sınırlayıcı."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = max(1, int(per_minute))
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < 60.0]
                if len(self._timestamps) < self.per_minute:
                    self._timestamps.append(now)
                    return
                wait = 60.0 - (now - self._timestamps[0])
            time.sleep(max(0.05, min(wait, 5.0)))


class BaseAdapter(ABC):
    """Tüm kaynak adaptörlerinin temel sınıfı."""

    adapter_name: str = "base"
    source_type: SourceType = SourceType.IOC_FEED
    default_category: SourceCategory = SourceCategory.STRUCTURED_API
    capabilities: set[str] = set()
    #: Kaynağın API anahtarının zorunlu olup olmadığı.
    requires_api_key: bool = False
    #: Adaptörün çalışması için gerekli ayar anahtarları.
    required_settings: tuple[str, ...] = ()

    def __init__(
        self,
        config: SourceConfig,
        settings: Any,
        session: Optional[Any] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self.source_config = config
        self.settings = settings
        self._session = session
        self.rate_limiter = rate_limiter or RateLimiter(getattr(settings, "requests_per_minute", 30))
        self.logger = logging.getLogger(f"opentip.adapters.{config.name}")
        self._last_run: dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Kimlik ve yapılandırma
    # ------------------------------------------------------------------ #
    @property
    def name(self) -> str:
        return self.source_config.name

    @property
    def enabled(self) -> bool:
        return bool(self.source_config.enabled)

    @property
    def settings_map(self) -> dict[str, Any]:
        return dict(self.source_config.settings or {})

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities

    def is_ready(self) -> bool:
        """Adaptörün sorguya hazır olup olmadığını döndürür.

        Etkin olsa bile eksik URL veya API anahtarı olan bir kaynak, analiz
        listesine alınmaz. Bu sayede veritabanında eski bir "enabled" kaydı
        kalsa bile kullanıcıya yanıltıcı hata gösterilmez.
        """
        if not self.enabled:
            return False
        if any(not self.setting(key) for key in self.required_settings):
            return False
        if self.requires_api_key and not self.secret():
            return False
        return True

    def setting(self, key: str, default: Any = None) -> Any:
        return self.settings_map.get(key, default)

    def secret(self, env_key: Optional[str] = None) -> Optional[str]:
        """Kimlik bilgisini ortam değişkeninden okur.

        API anahtarları veritabanına veya kaynak koduna yazılmaz (PRD 16).
        """
        key = env_key or self.setting("api_key_env")
        if not key:
            return None
        return getattr(self.settings, str(key).lower(), None)

    def require_config(self, key: str) -> str:
        value = self.setting(key)
        if not value:
            raise AdapterConfigError(
                f"{self.name}: '{key}' ayarı eksik. .env dosyasından yapılandırın."
            )
        return str(value)

    @property
    def session(self) -> Any:
        if self._session is None:
            import requests  # yerel içe aktarma: test ortamında gereksiz bağımlılık olmasın

            self._session = requests.Session()
            self._session.headers.update({"User-Agent": getattr(self.settings, "user_agent", "OpenTIP/2.0")})
        return self._session

    # ------------------------------------------------------------------ #
    # Güvenli HTTP katmanı
    # ------------------------------------------------------------------ #
    _BLOCKED_HOSTS = {
        "localhost",
        "metadata.google.internal",
        "169.254.169.254",
        "::1",
    }

    @classmethod
    def _validate_url(cls, url: str) -> None:
        """SSRF riskini azaltmak için URL şemasını ve hedefini doğrular (PRD 16)."""
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise AdapterConfigError(f"Yalnızca http/https desteklenir: {url}")
        host = (parts.hostname or "").lower()
        if not host:
            raise AdapterConfigError(f"Geçersiz URL: {url}")
        if host in cls._BLOCKED_HOSTS:
            raise AdapterConfigError(f"Engellenen hedef: {host}")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
            raise AdapterConfigError(f"Özel/dahili adreslere istek engellendi: {host}")

    def request(
        self,
        method: str,
        url: str,
        *,
        timeout: Optional[int] = None,
        retries: Optional[int] = None,
        **kwargs: Any,
    ) -> Any:
        """Yeniden deneme, zaman aşımı ve hız sınırı uygulayan HTTP isteği."""
        self._validate_url(url)
        timeout = timeout or getattr(self.settings, "http_timeout", 15)
        retries = retries if retries is not None else getattr(self.settings, "http_max_retries", 3)
        backoff = float(getattr(self.settings, "http_backoff_seconds", 1.5))
        last_error: Optional[Exception] = None

        for attempt in range(max(1, retries + 1)):
            self.rate_limiter.acquire()
            try:
                response = self.session.request(method, url, timeout=timeout, **kwargs)
            except Exception as exc:  # ağ hatası
                last_error = exc
                if attempt >= retries:
                    raise AdapterUnavailable(f"{self.name}: bağlantı hatası ({exc})") from exc
                time.sleep(backoff * (2**attempt))
                continue

            status_code = getattr(response, "status_code", 0)
            if status_code == 429 or 500 <= status_code < 600:
                last_error = AdapterUnavailable(
                    f"{self.name}: kaynak geçici olarak kullanılamıyor (HTTP {status_code})"
                )
                if attempt >= retries:
                    raise last_error
                retry_after = 0.0
                try:
                    retry_after = float(response.headers.get("Retry-After", 0))
                except (TypeError, ValueError):
                    retry_after = 0.0
                time.sleep(retry_after or backoff * (2**attempt))
                continue

            if status_code == 401 or status_code == 403:
                raise AdapterError(
                    f"{self.name}: yetkilendirme hatası (HTTP {status_code}). "
                    "API anahtarını ve erişim izinlerini kontrol edin."
                )
            if status_code == 404:
                return response
            if status_code >= 400:
                raise AdapterError(f"{self.name}: istek başarısız (HTTP {status_code})")
            return response

        raise AdapterUnavailable(f"{self.name}: istek tamamlanamadı ({last_error})")

    @staticmethod
    def json_body(response: Any) -> Any:
        try:
            return response.json()
        except Exception as exc:
            raise AdapterError(f"Kaynak yanıtı JSON olarak ayrıştırılamadı: {exc}") from exc

    # ------------------------------------------------------------------ #
    # PRD 9.3 arayüzü
    # ------------------------------------------------------------------ #
    @abstractmethod
    def check_connection(self) -> bool:
        """Kaynağın erişilebilirliğini kontrol eder."""

    def fetch_updates(self, **kwargs: Any) -> list[Any]:
        """Yeni veya değişen kayıtları getirir. Desteklenmiyorsa hata yükseltir."""
        raise AdapterNotSupported(f"{self.name}: fetch_updates desteklenmiyor.")

    def normalize_record(self, raw: Any) -> Any:
        """Ham kaydı ortak veri modeline dönüştürür. Desteklenmiyorsa hata yükseltir."""
        raise AdapterNotSupported(f"{self.name}: normalize_record desteklenmiyor.")

    def lookup_ioc(self, ioc: IOCInput) -> list[IOCRecord]:
        """Verilen IOC'yi bu kaynakta arar. Desteklenmiyorsa hata yükseltir."""
        raise AdapterNotSupported(f"{self.name}: IOC sorgusu desteklenmiyor.")

    def get_source_status(self) -> SourceHealth:
        """Son kontrol, hata ve durum bilgilerini döndürür."""
        return SourceHealth(
            source_name=self.name,
            source_id=self.source_config.source_id,
            status=self._last_run.get("status", SourceStatus.UNKNOWN),
            message=self._last_run.get("message", ""),
            last_checked_at=self._last_run.get("checked_at"),
            last_success_at=self._last_run.get("success_at"),
            last_error_at=self._last_run.get("error_at"),
            consecutive_failures=self._last_run.get("failures", 0),
            check_interval_minutes=self.source_config.check_interval_minutes,
            enabled=self.enabled,
        )

    def record_run(self, *, success: bool, message: str = "") -> None:
        """Adaptörün yerel çalışma durumunu günceller."""
        now = utcnow()
        self._last_run["checked_at"] = now
        self._last_run["status"] = SourceStatus.OK if success else SourceStatus.UNAVAILABLE
        self._last_run["message"] = message
        if success:
            self._last_run["success_at"] = now
            self._last_run["failures"] = 0
        else:
            self._last_run["error_at"] = now
            self._last_run["failures"] = int(self._last_run.get("failures", 0)) + 1

    # ------------------------------------------------------------------ #
    def describe(self) -> dict[str, Any]:
        """Arayüzde gösterilecek adaptör özeti."""
        return {
            "name": self.name,
            "adapter": self.adapter_name,
            "source_type": str(self.source_type),
            "category": str(self.source_config.category),
            "enabled": self.enabled,
            "capabilities": sorted(self.capabilities),
            "check_interval_minutes": self.source_config.check_interval_minutes,
            "reliability": self.source_config.reliability,
            "notes": self.source_config.notes,
        }

    def close(self) -> None:
        if self._session is not None:
            try:
                self._session.close()
            except Exception:  # pragma: no cover - kapatma hatası yok sayılır
                pass
            self._session = None


def chunked(items: Sequence[Any], size: int) -> list[list[Any]]:
    return [list(items[i : i + size]) for i in range(0, len(items), size)]
