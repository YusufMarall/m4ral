"""deepdarkCTI kaynak kataloğu veri modelleri.

deepdarkCTI bir API değil, kategori kategori tutulan **küratörlü bir kaynak
listesidir**. Bu projede katalog kayıtları bulgu (finding) olarak üretilmez;
ayrı bir referans katmanında saklanır. Analist uygun gördüğü kaydı bilinçli
olarak izlemeye alırsa o zaman `darkweb_source` adaptörü devreye girer.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from .enums import CatalogNetwork, CatalogStatus
from .ioc import utcnow


class CatalogEntry(BaseModel):
    """Katalogdaki tek bir kaynak kaydı (bir forum, pazar, çete sızıntı sitesi...)."""

    model_config = {"use_enum_values": False}

    entry_id: Optional[int] = None
    #: Kataloğun adı; şimdilik her zaman "deepdarkcti".
    catalog: str = "deepdarkcti"
    #: Kategori anahtarı (ör. "ransomware_gang").
    category: str
    category_label: str = ""
    name: str
    url: Optional[str] = None
    network: CatalogNetwork = CatalogNetwork.UNKNOWN
    status: CatalogStatus = CatalogStatus.UNKNOWN
    description: str = ""
    #: Markdown tablosundaki diğer sütunlar (ör. "tox_id", "rss_feed").
    columns: dict[str, str] = Field(default_factory=dict)
    #: Satırın ham içeriğinin sha256 özeti (değişiklik tespiti için).
    content_digest: str = ""
    #: Analist bu kaydı izlemeye aldı mı?
    tracked: bool = False
    #: İzlemeye alındıysa oluşturulan kaynak adı.
    source_name: Optional[str] = None
    notes: str = ""
    first_synced_at: datetime = Field(default_factory=utcnow)
    last_synced_at: datetime = Field(default_factory=utcnow)

    @property
    def fingerprint(self) -> str:
        """Tekilleştirme anahtarı. Aynı kategori içinde isim + URL eşleşir."""
        raw = f"{self.catalog}|{self.category}|{self.name.strip().casefold()}|{self.url or ''}"
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()

    @property
    def is_tor(self) -> bool:
        return self.network == CatalogNetwork.TOR


class CatalogSync(BaseModel):
    """Tek bir kategorinin eşitleme çalışmasının kaydı."""

    sync_id: Optional[int] = None
    catalog: str = "deepdarkcti"
    category: str
    category_label: str = ""
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None
    #: running | ok | failed
    status: str = "running"
    entries_fetched: int = 0
    entries_created: int = 0
    entries_updated: int = 0
    entries_missing: int = 0
    error_message: Optional[str] = None

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()


__all__ = ["CatalogEntry", "CatalogSync"]
