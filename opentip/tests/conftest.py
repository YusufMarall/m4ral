"""Ortak pytest fixture'ları ve sahte (mock) yardımcılar.

Testler gerçek ağ erişimi yapmaz; tüm HTTP etkileşimi sahte oturumlar
üzerinden yürütülür (PRD Bölüm 17 "test yaklaşımı").
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Sequence

import pytest

from config import Settings
from models import SourceConfig, SourceType
from storage import Database, Repositories


# --------------------------------------------------------------------------- #
# Sahte HTTP katmanı
# --------------------------------------------------------------------------- #
class FakeResponse:
    """`requests.Response` yerine kullanılan asgari sahte yanıt."""

    def __init__(
        self,
        status_code: int = 200,
        payload: Any = None,
        headers: Optional[dict[str, str]] = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = text

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("Sahte yanıt JSON gövdesi içermiyor")
        return self._payload


class FakeSession:
    """Sırayla yanıt döndüren sahte oturum; yapılan istekleri kaydeder."""

    def __init__(self, responses: Sequence[Any] = ()) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []
        self.headers: dict[str, str] = {}
        self.closed = False

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        if not self.responses:
            raise AssertionError("Beklenmeyen ek HTTP isteği")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        self.closed = True


# --------------------------------------------------------------------------- #
# Sahte izleme adaptörü
# --------------------------------------------------------------------------- #
class FakeMonitorAdapter:
    """`SourceMonitor` için asgari adaptör taklidi."""

    adapter_name = "fake"
    source_type = SourceType.BREACH_FEED
    capabilities = {"fetch_updates", "connection_check"}
    requires_api_key = False

    def __init__(
        self,
        config: SourceConfig,
        settings: Any,
        raw_records: Sequence[Any] = (),
        error: Optional[Exception] = None,
    ) -> None:
        self.source_config = config
        self.settings = settings
        self.raw_records = list(raw_records)
        self.error = error
        self.logger = logging.getLogger(f"tests.{config.name}")
        self.closed = False

    @property
    def name(self) -> str:
        return self.source_config.name

    @property
    def enabled(self) -> bool:
        return bool(self.source_config.enabled)

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities

    def fetch_updates(self, **kwargs: Any) -> list[Any]:
        if self.error is not None:
            raise self.error
        return list(self.raw_records)

    def normalize_record(self, raw: Any) -> Any:
        return raw

    def check_connection(self) -> bool:
        return self.error is None

    def close(self) -> None:
        self.closed = True


# --------------------------------------------------------------------------- #
# Fixture'lar
# --------------------------------------------------------------------------- #
@pytest.fixture
def settings(tmp_path) -> Settings:
    """Ağ erişimi yapmayan, geçici dizin kullanan test ayarları."""
    return Settings(
        database_path=str(tmp_path / "opentip.db"),
        report_output_dir=str(tmp_path / "reports"),
        http_backoff_seconds=0.0,
        http_timeout=2,
        requests_per_minute=1000,
    )


@pytest.fixture
def repos(settings: Settings) -> Repositories:
    """Şeması oluşturulmuş, dosya tabanlı geçici veritabanı."""
    db = Database(settings.database_file)
    db.initialize()
    return Repositories(db=db)


@pytest.fixture
def register_source(repos: Repositories):
    """Veritabanına kaynak yapılandırması ekleyen yardımcı."""

    def _register(
        name: str = "fake",
        adapter: str = "fake",
        source_type: SourceType = SourceType.BREACH_FEED,
        **kwargs: Any,
    ) -> SourceConfig:
        config = SourceConfig(
            name=name, adapter=adapter, source_type=source_type, **kwargs
        )
        repos.sources.upsert(config)
        stored = repos.sources.get(name)
        assert stored is not None
        return stored

    return _register


@pytest.fixture
def make_response():
    """`FakeResponse` üreten fabrika."""

    def _make(
        status_code: int = 200,
        payload: Any = None,
        headers: Optional[dict[str, str]] = None,
        text: str = "",
    ) -> FakeResponse:
        return FakeResponse(status_code, payload=payload, headers=headers, text=text)

    return _make


@pytest.fixture
def make_session():
    """`FakeSession` üreten fabrika."""

    def _make(responses: Sequence[Any] = ()) -> FakeSession:
        return FakeSession(responses)

    return _make


@pytest.fixture
def make_adapter():
    """Sahte izleme adaptörü üreten fabrika."""

    def _make(
        config: SourceConfig,
        settings: Any,
        raw_records: Sequence[Any] = (),
        error: Optional[Exception] = None,
        source_type: SourceType = SourceType.BREACH_FEED,
    ) -> FakeMonitorAdapter:
        class _Adapter(FakeMonitorAdapter):
            pass

        _Adapter.source_type = source_type
        instance = _Adapter(config, settings, raw_records=raw_records, error=error)
        return instance

    return _make
