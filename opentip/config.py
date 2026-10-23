"""OpenTIP uygulama yapılandırması.

Tüm gizli değerler ortam değişkenlerinden veya `.env` dosyasından okunur.
API anahtarları kaynak koduna yazılmaz ve raporlara dahil edilmez.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    """Uygulama ayarları. Ortam değişkenleri alan adlarıyla büyük/küçük harf duyarsız eşleşir."""

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Uygulama ---
    app_name: str = "OpenTIP"
    environment: str = "development"
    log_level: str = "INFO"

    # --- Depolama ---
    database_path: str = str(BASE_DIR / "data" / "opentip.db")
    report_output_dir: str = str(BASE_DIR / "reports_output")

    # --- HTTP davranışı ---
    http_timeout: int = 15
    http_max_retries: int = 3
    http_backoff_seconds: float = 1.5
    requests_per_minute: int = 30
    user_agent: str = "OpenTIP/2.0 (+threat-intelligence-platform)"

    # --- Zamanlayıcı ---
    scheduler_enabled: bool = False
    default_check_interval_minutes: int = 60

    # --- IOC kaynakları ---
    otx_api_key: Optional[str] = None
    otx_enabled: bool = True

    threatfox_api_key: Optional[str] = None
    threatfox_enabled: bool = False

    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    misp_verify_tls: bool = True
    misp_enabled: bool = False

    # --- Breach Intelligence ---
    xposedornot_api_key: Optional[str] = None
    xposedornot_enabled: bool = False

    breach_feed_url: Optional[str] = None
    breach_feed_api_key: Optional[str] = None
    breach_feed_enabled: bool = False

    # --- Dark Web Monitoring (izinli kaynak) ---
    darkweb_source_url: Optional[str] = None
    darkweb_source_api_key: Optional[str] = None
    darkweb_source_enabled: bool = False

    # --- Dark Web Kaynak Kataloğu (deepdarkCTI) ---
    # Küratörlü kaynak listesi; bulgu üretmez, referans katmanıdır.
    deepdarkcti_base_url: str = (
        "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/"
    )
    deepdarkcti_enabled: bool = True

    @property
    def database_file(self) -> Path:
        return Path(self.database_path).expanduser().resolve()

    @property
    def report_dir(self) -> Path:
        return Path(self.report_output_dir).expanduser().resolve()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Ayarları tek örnek (singleton) olarak döndürür."""
    return Settings()
