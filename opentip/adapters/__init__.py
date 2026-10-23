"""Kaynak adaptörleri ve kayıt defteri.

Yeni bir kaynak eklemek için:
1. `BaseAdapter`'ı uygulayan yeni bir sınıf yazın.
2. `ADAPTER_REGISTRY` sözlüğüne kaydedin.
3. `default_source_configs()` içinde varsayılan yapılandırmasını tanımlayın.

Analiz motorunun geri kalanının değiştirilmesi gerekmez (PRD 6, 20).
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from models import SourceCategory, SourceConfig, SourceType
from storage import Repositories

from .base import (
    CAP_CONNECTION_CHECK,
    CAP_FETCH_UPDATES,
    CAP_IOC_LOOKUP,
    AdapterConfigError,
    AdapterError,
    AdapterNotSupported,
    AdapterUnavailable,
    BaseAdapter,
    RateLimiter,
)
from .breach_feed import BreachFeedAdapter
from .darkweb_source import DarkWebSourceAdapter
from .deepdarkcti import DeepDarkCTIAdapter, build_deepdarkcti_adapter
from .misp import MISPAdapter
from .otx import OTXAdapter
from .threatfox import ThreatFoxAdapter
from .xposedornot import XposedOrNotAdapter

ADAPTER_REGISTRY: dict[str, type[BaseAdapter]] = {
    OTXAdapter.adapter_name: OTXAdapter,
    ThreatFoxAdapter.adapter_name: ThreatFoxAdapter,
    MISPAdapter.adapter_name: MISPAdapter,
    XposedOrNotAdapter.adapter_name: XposedOrNotAdapter,
    BreachFeedAdapter.adapter_name: BreachFeedAdapter,
    DarkWebSourceAdapter.adapter_name: DarkWebSourceAdapter,
    # Katalog adaptörü bulgu üretmez; yalnızca deepdarkCTI kataloğunu indirir.
    DeepDarkCTIAdapter.adapter_name: DeepDarkCTIAdapter,
}


def default_source_configs(settings: Any) -> list[SourceConfig]:
    """`.env` ayarlarından varsayılan kaynak yapılandırmalarını üretir.

    Kimlik bilgilerinin kendisi burada tutulmaz; yalnızca okunacak ortam
    değişkeninin adı (`api_key_env`) saklanır (PRD 16).
    """
    configs: list[SourceConfig] = [
        SourceConfig(
            name="otx",
            adapter="otx",
            source_type=SourceType.IOC_FEED,
            category=SourceCategory.STRUCTURED_API,
            enabled=bool(getattr(settings, "otx_enabled", True)),
            check_interval_minutes=60,
            reliability=0.6,
            settings={"api_key_env": "OTX_API_KEY"},
            notes="AlienVault OTX topluluk pulse akışı. Anahtar olmadan kısıtlı çalışır.",
        ),
        SourceConfig(
            name="threatfox",
            adapter="threatfox",
            source_type=SourceType.IOC_FEED,
            category=SourceCategory.STRUCTURED_API,
            enabled=bool(getattr(settings, "threatfox_enabled", False)),
            check_interval_minutes=120,
            reliability=0.75,
            settings={
                "url": "https://threatfox-api.abuse.ch/api/v1/",
                "api_key_env": "THREATFOX_API_KEY",
            },
            notes="abuse.ch ThreatFox. Ücretsiz topluluk API'si Auth-Key gerektirir.",
        ),
        SourceConfig(
            name="misp",
            adapter="misp",
            source_type=SourceType.IOC_FEED,
            category=SourceCategory.STRUCTURED_API,
            enabled=bool(getattr(settings, "misp_enabled", False))
            and bool(getattr(settings, "misp_url", None)),
            check_interval_minutes=180,
            reliability=0.8,
            settings={
                "url": getattr(settings, "misp_url", None),
                "api_key_env": "MISP_API_KEY",
            },
            notes="Yalnızca yetkili erişim. TLS doğrulaması varsayılan olarak açıktır.",
        ),
        SourceConfig(
            name="xposedornot",
            adapter="xposedornot",
            source_type=SourceType.BREACH_FEED,
            category=SourceCategory.STRUCTURED_API,
            enabled=bool(getattr(settings, "xposedornot_enabled", False)),
            check_interval_minutes=360,
            reliability=0.7,
            settings={"api_key_env": "XPOSEDORNOT_API_KEY"},
            notes=(
                "XposedOrNot public breach sorgusu anahtarsız çalışır. "
                "Doğrulanmış domain monitoring için API anahtarı eklenebilir."
            ),
        ),
        SourceConfig(
            name="breach_feed",
            adapter="breach_feed",
            source_type=SourceType.BREACH_FEED,
            category=SourceCategory.STRUCTURED_API,
            enabled=bool(getattr(settings, "breach_feed_enabled", False))
            and bool(getattr(settings, "breach_feed_url", None)),
            check_interval_minutes=360,
            reliability=0.7,
            settings={
                "url": getattr(settings, "breach_feed_url", None),
                "api_key_env": "BREACH_FEED_API_KEY",
                "auth_scheme": "bearer",
            },
            notes="İzinli breach intelligence sağlayıcısı (yapılandırılmış akış).",
        ),
        SourceConfig(
            name="darkweb_source",
            adapter="darkweb_source",
            source_type=SourceType.DARKWEB_SOURCE,
            category=SourceCategory.AUTHORIZED_WEB,
            # Erişim izni beyan edilmeden çalıştırılmaz (PRD 9.6).
            enabled=False,
            check_interval_minutes=720,
            reliability=0.4,
            settings={
                "url": getattr(settings, "darkweb_source_url", None),
                "api_key_env": "DARKWEB_SOURCE_API_KEY",
                "confirmed_authorized": False,
                "terms_reviewed": False,
            },
            notes=(
                "Yalnızca kullanımına izin verilen yapılandırılmış kaynak. "
                "Çalıştırmadan önce izin ve kullanım koşulları onaylanmalıdır."
            ),
        ),
    ]
    return configs


def sync_sources(repos: Repositories, settings: Any) -> list[SourceConfig]:
    """Varsayılan kaynakları veritabanına ekler (var olanları değiştirmez)."""
    for config in default_source_configs(settings):
        if repos.sources.get(config.name) is None:
            repos.sources.upsert(config)
            repos.audit.log(
                "source_registered",
                entity_type="source",
                entity_id=config.name,
                detail={
                    "adapter": config.adapter,
                    "enabled": config.enabled,
                    "source_type": str(config.source_type),
                },
            )
    return repos.sources.list()


def update_source_settings(
    repos: Repositories, name: str, updates: dict[str, Any], actor: str = "analyst"
) -> None:
    """Bir kaynağın ayarlarını ve/veya etkinlik durumunu günceller."""
    config = repos.sources.get(name)
    if config is None:
        raise KeyError(f"Kaynak bulunamadı: {name}")

    merged = {**config.settings, **updates}
    config.settings = merged
    repos.sources.upsert(config)

    if "enabled" in updates:
        repos.sources.set_enabled(name, bool(updates["enabled"]))
        config.enabled = bool(updates["enabled"])

    repos.audit.log(
        "source_settings_updated",
        entity_type="source",
        entity_id=name,
        detail={"keys": sorted(updates.keys())},
        actor=actor,
    )


def build_adapter(config: SourceConfig, settings: Any, session: Optional[Any] = None) -> BaseAdapter:
    """Yapılandırmadan adaptör örneği üretir."""
    adapter_cls = ADAPTER_REGISTRY.get(config.adapter)
    if adapter_cls is None:
        raise AdapterConfigError(f"Bilinmeyen adaptör: {config.adapter}")
    return adapter_cls(config, settings, session=session)


def build_adapters(
    configs: Sequence[SourceConfig], settings: Any, session: Optional[Any] = None
) -> list[BaseAdapter]:
    """Birden fazla yapılandırmadan adaptör listesi üretir."""
    limiter = RateLimiter(getattr(settings, "requests_per_minute", 30))
    adapters: list[BaseAdapter] = []
    for config in configs:
        adapter_cls = ADAPTER_REGISTRY.get(config.adapter)
        if adapter_cls is None:
            continue
        adapters.append(adapter_cls(config, settings, session=session, rate_limiter=limiter))
    return adapters


def build_adapters_from_repos(
    repos: Repositories, settings: Any, session: Optional[Any] = None
) -> list[BaseAdapter]:
    """Veritabanındaki kaynak yapılandırmalarından adaptörleri üretir."""
    return build_adapters(repos.sources.list(), settings, session=session)


__all__ = [
    "ADAPTER_REGISTRY",
    "BaseAdapter",
    "AdapterError",
    "AdapterUnavailable",
    "AdapterConfigError",
    "AdapterNotSupported",
    "RateLimiter",
    "CAP_IOC_LOOKUP",
    "CAP_FETCH_UPDATES",
    "CAP_CONNECTION_CHECK",
    "OTXAdapter",
    "ThreatFoxAdapter",
    "MISPAdapter",
    "XposedOrNotAdapter",
    "BreachFeedAdapter",
    "DarkWebSourceAdapter",
    "DeepDarkCTIAdapter",
    "build_deepdarkcti_adapter",
    "default_source_configs",
    "sync_sources",
    "update_source_settings",
    "build_adapter",
    "build_adapters",
    "build_adapters_from_repos",
]
