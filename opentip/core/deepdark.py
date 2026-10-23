"""deepdarkCTI kaynak kataloğu: ayrıştırma, eşitleme ve eşleştirme.

deepdarkCTI (https://github.com/fastfire/deepdarkCTI) bir API değil, kategori
kategori tutulan **küratörlü bir kaynak kataloğudur** (fidye yazılımı çetesi
sızıntı siteleri, forumlar, pazarlar, Telegram kanalları, RaaS siteleri...).

Bu modül o kataloğu OpenTIP panosuna taşır:

* Markdown tabloları ayrıştırılır ve `catalog_entries` tablosunda saklanır.
* Kayıtlar **bulgu değildir**; doğrulama/risk akışına girmez (PRD 8.5, 11).
* Analist bir kaydı bilinçli olarak izlemeye alırsa `darkweb_source` adaptörü
  için bir kaynak yapılandırması oluşturulur. İzin beyanı yapılmadan
  (`confirmed_authorized`) o kaynak çalışmaz (PRD 9.6).

Modül hiçbir ağ taraması yapmaz; yalnızca herkese açık depo dosyalarını okur
ve Tor ağının tamamının taranmadığını açıkça beyan eder.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Optional, Protocol, Sequence
from urllib.parse import urlsplit

from models import (
    CatalogEntry,
    CatalogNetwork,
    CatalogStatus,
    CatalogSync,
    SourceCategory,
    SourceConfig,
    SourceType,
    utcnow,
)

from .normalizer import sanitize_text

CATALOG_NAME = "deepdarkcti"


# --------------------------------------------------------------------------- #
# Kategori tanımları (deepdarkCTI deposundaki dosya adlarıyla birebir)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CatalogCategory:
    """Katalogdaki bir kategori ve karşılık gelen markdown dosyası."""

    key: str
    filename: str
    label: str
    description: str


DEEPDARK_CATEGORIES: tuple[CatalogCategory, ...] = (
    CatalogCategory(
        "ransomware_gang",
        "ransomware_gang.md",
        "Fidye yazılımı çeteleri / sızıntı siteleri",
        "Çete sızıntı (leak) siteleri, mağdur yayın sayfaları ve takip servisleri.",
    ),
    CatalogCategory(
        "maas",
        "maas.md",
        "Malware-as-a-Service",
        "Kiralık kötü amaçlı yazılım hizmetleri.",
    ),
    CatalogCategory(
        "forum",
        "forum.md",
        "Yeraltı forumları",
        "Sızıntı, karting ve hack forumları (clearnet ve onion).",
    ),
    CatalogCategory(
        "markets",
        "markets.md",
        "Pazarlar",
        "Yasadışı ürün ve veri satış platformları.",
    ),
    CatalogCategory(
        "telegram_infostealer",
        "telegram_infostealer.md",
        "Telegram bilgi hırsızı kanalları",
        "Stealer log ve sızdırılmış kimlik bilgisi paylaşan Telegram kanalları.",
    ),
    CatalogCategory(
        "discord",
        "discord.md",
        "Discord sunucuları",
        "Suç faaliyetleri için kullanılan Discord toplulukları.",
    ),
    CatalogCategory(
        "rat",
        "rat.md",
        "Uzaktan erişim truva atları (RAT)",
        "RAT panelleri ve satış kanalları.",
    ),
    CatalogCategory(
        "exploits",
        "exploits.md",
        "Exploit kaynakları",
        "Exploit satış ve dağıtım platformları.",
    ),
    CatalogCategory(
        "cve_most_exploited",
        "cve_most_exploited.md",
        "En çok sömürülen CVE'ler",
        "Aktif olarak sömürülen zafiyetler ve referansları.",
    ),
    CatalogCategory(
        "phishing",
        "phishing.md",
        "Oltalama kaynakları",
        "Phishing kit ve kampanya altyapıları.",
    ),
    CatalogCategory(
        "malware_samples",
        "malware_samples.md",
        "Zararlı yazılım örnekleri",
        "Örnek paylaşım ve analiz platformları.",
    ),
    CatalogCategory(
        "defacement",
        "defacement.md",
        "Defacement arşivleri",
        "Site defacement kayıtları.",
    ),
    CatalogCategory(
        "counterfeit_goods",
        "counterfeit_goods.md",
        "Sahte ürün satışı",
        "Taklit ürün ve marka istismarı platformları.",
    ),
    CatalogCategory(
        "search_engines",
        "search_engines.md",
        "Karanlık ağ arama motorları",
        "Onion/dark web arama servisleri.",
    ),
    CatalogCategory(
        "commercial_services",
        "commercial_services.md",
        "Ticari servisler",
        "Suç ekosistemine hizmet veren ticari sağlayıcılar.",
    ),
    CatalogCategory(
        "others",
        "others.md",
        "Diğer kaynaklar",
        "Sınıflandırılamayan ek kaynaklar.",
    ),
    CatalogCategory(
        "methods",
        "methods.md",
        "Yöntemler ve teknikler",
        "Kaynak araştırma ve analiz yöntemleri (bilgi amaçlı, adres listesi değildir).",
    ),
)

CATEGORY_MAP: dict[str, CatalogCategory] = {c.key: c for c in DEEPDARK_CATEGORIES}


def category_by_key(key: str) -> Optional[CatalogCategory]:
    return CATEGORY_MAP.get(key)


def category_label(key: str) -> str:
    category = CATEGORY_MAP.get(key)
    return category.label if category else key


# --------------------------------------------------------------------------- #
# Markdown tablo ayrıştırma
# --------------------------------------------------------------------------- #
_MD_LINK_RE = re.compile(r"\[([^\]]*)\]\(\s*([^)\s]+)\s*\)")
_BARE_URL_RE = re.compile(r"https?://[^\s|\]\)]+")
_SEPARATOR_RE = re.compile(r"^:?-{2,}:?$")
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_KEY_RE = re.compile(r"[^a-z0-9]+")

#: İsim / durum / açıklama sütunlarının olası başlıkları.
_NAME_KEYS = ("name", "site", "isim", "ad")
_STATUS_KEYS = ("status", "durum")
_DESCRIPTION_KEYS = ("description", "desc", "aciklama", "notes", "not")


class MarkdownFetcher(Protocol):
    """Katalog servisinin ihtiyaç duyduğu asgari indirme arayüzü."""

    def fetch_markdown(self, path: str) -> str:  # pragma: no cover - protokol
        ...

    def check_connection(self) -> bool:  # pragma: no cover - protokol
        ...


def strip_markdown(text: Any) -> str:
    """Markdown bağlantı sözdizimini kaldırıp düz metin bırakır."""
    value = _MD_LINK_RE.sub(lambda m: m.group(1) or m.group(2), str(text or ""))
    value = _TAG_RE.sub(" ", value)
    return _WS_RE.sub(" ", value).strip()


def normalize_column_key(header: str) -> str:
    """Sütun başlığını anahtar biçimine indirger (ör. "Tox ID" -> "tox_id")."""
    return _KEY_RE.sub("_", str(header or "").strip().casefold()).strip("_")


def split_table_row(line: str) -> list[str]:
    """Markdown tablo satırını hücrelere ayırır (kaçışlı `|` korunur)."""
    parts = re.split(r"(?<!\\)\|", line.strip())
    if parts and not parts[0].strip():
        parts = parts[1:]
    if parts and not parts[-1].strip():
        parts = parts[:-1]
    return [p.replace("\\|", "|").strip() for p in parts]


def parse_markdown_table(text: str) -> tuple[list[str], list[list[str]]]:
    """İlk tablo başlığını ve veri satırlarını döndürür."""
    header: list[str] = []
    rows: list[list[str]] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = split_table_row(line)
        if not cells:
            continue
        if not header:
            header = cells
            continue
        if all((not c) or _SEPARATOR_RE.match(c) for c in cells):
            continue  # ayırıcı satır (| --- | --- |)
        padded = list(cells[: len(header)]) + [""] * max(0, len(header) - len(cells))
        rows.append(padded)
    return header, rows


def detect_network(url: Optional[str]) -> CatalogNetwork:
    """URL'nin Tor (onion) mu, clearnet mi olduğunu belirler."""
    if not url:
        return CatalogNetwork.UNKNOWN
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        return CatalogNetwork.UNKNOWN
    if host.endswith(".onion"):
        return CatalogNetwork.TOR
    if parts.scheme in ("http", "https"):
        return CatalogNetwork.CLEARNET
    return CatalogNetwork.UNKNOWN


def normalize_status(value: Any) -> CatalogStatus:
    """Kaynağın beyan ettiği ONLINE/OFFLINE değerini ortak duruma çevirir."""
    text = str(value or "").strip().casefold()
    if "offline" in text:
        return CatalogStatus.OFFLINE
    if "online" in text:
        return CatalogStatus.ONLINE
    return CatalogStatus.UNKNOWN


def _extract_name_and_url(cell: str) -> tuple[str, Optional[str]]:
    """İsim hücresinden görünen adı ve bağlantıyı çıkarır."""
    raw = str(cell or "").strip()
    match = _MD_LINK_RE.search(raw)
    if match:
        name = strip_markdown(match.group(1)) or match.group(2)
        return name, match.group(2).strip()
    bare = _BARE_URL_RE.search(raw)
    if bare:
        return strip_markdown(raw) or bare.group(0), bare.group(0)
    return strip_markdown(raw), None


def _row_digest(cells: Sequence[str]) -> str:
    payload = "|".join(cells).encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


def parse_catalog_entries(markdown: str, category: CatalogCategory) -> list[CatalogEntry]:
    """Bir kategorinin markdown içeriğini katalog kayıtlarına dönüştürür."""
    header, rows = parse_markdown_table(markdown)
    if not header:
        return []

    keys = [normalize_column_key(h) for h in header]
    name_idx = next((keys.index(k) for k in _NAME_KEYS if k in keys), 0)
    status_idx = next((keys.index(k) for k in _STATUS_KEYS if k in keys), None)
    desc_idx = next((keys.index(k) for k in _DESCRIPTION_KEYS if k in keys), None)

    entries: dict[str, CatalogEntry] = {}
    for row in rows:
        raw_name = row[name_idx] if name_idx < len(row) else ""
        if not raw_name.strip():
            continue
        name, url = _extract_name_and_url(raw_name)
        if not name:
            continue

        columns: dict[str, str] = {}
        reserved = {name_idx}
        if status_idx is not None:
            reserved.add(status_idx)
        if desc_idx is not None:
            reserved.add(desc_idx)
        for index, key in enumerate(keys):
            if index >= len(row) or not key or index in reserved:
                continue
            value = sanitize_text(row[index], max_length=300)
            if value:
                columns[key] = value

        description = ""
        if desc_idx is not None and desc_idx < len(row):
            description = sanitize_text(row[desc_idx], max_length=600)

        entry = CatalogEntry(
            catalog=CATALOG_NAME,
            category=category.key,
            category_label=category.label,
            name=sanitize_text(name, max_length=200),
            url=url,
            network=detect_network(url),
            status=normalize_status(row[status_idx]) if status_idx is not None else CatalogStatus.UNKNOWN,
            description=description,
            columns=columns,
            content_digest=_row_digest(row),
        )
        # Aynı isim + URL birden fazla satırda geçebilir; son kayıt geçerlidir.
        entries[entry.fingerprint] = entry

    return list(entries.values())


# --------------------------------------------------------------------------- #
# Katalog servisi
# --------------------------------------------------------------------------- #
def _slug(value: str, max_length: int = 40) -> str:
    text = _KEY_RE.sub("_", str(value or "").strip().casefold()).strip("_")
    return (text or "kayit")[:max_length].strip("_") or "kayit"


class DeepDarkCatalogService:
    """deepdarkCTI kataloğunu eşitler, arar ve izlemeye alınacak kaynağa çevirir."""

    def __init__(self, repos: Any, fetcher: MarkdownFetcher) -> None:
        self.repos = repos
        self.fetcher = fetcher

    # ------------------------------------------------------------------ #
    def categories(self) -> tuple[CatalogCategory, ...]:
        return DEEPDARK_CATEGORIES

    def check_connection(self) -> bool:
        return bool(self.fetcher.check_connection())

    # ------------------------------------------------------------------ #
    def sync(
        self,
        category_keys: Optional[Sequence[str]] = None,
        actor: str = "analyst",
    ) -> list[CatalogSync]:
        """Seçili kategorileri (varsayılan: tümü) eşitler.

        Tek bir kategori hata verirse diğerleri etkilenmez; hata kaydı
        `catalog_syncs` tablosuna yazılır (PRD 9.4 ile aynı yaklaşım).
        """
        keys = list(category_keys) if category_keys else [c.key for c in DEEPDARK_CATEGORIES]
        results: list[CatalogSync] = []

        for key in keys:
            category = CATEGORY_MAP.get(key)
            if category is None:
                continue

            started = utcnow()
            sync_id = self.repos.catalog_syncs.start(key, category.label)
            try:
                markdown = self.fetcher.fetch_markdown(category.filename)
                entries = parse_catalog_entries(markdown, category)
            except Exception as exc:  # kaynak hatası, eşleşme yokluğundan ayrıdır
                self.repos.catalog_syncs.finish(
                    sync_id, status="failed", error_message=str(exc)
                )
                self.repos.audit.log(
                    "catalog_sync_failed",
                    entity_type="catalog",
                    entity_id=key,
                    detail={"error": str(exc)},
                    actor=actor,
                )
                results.append(
                    CatalogSync(
                        sync_id=sync_id,
                        category=key,
                        category_label=category.label,
                        started_at=started,
                        finished_at=utcnow(),
                        status="failed",
                        error_message=str(exc),
                    )
                )
                continue

            created = updated = 0
            for entry in entries:
                _entry_id, action = self.repos.catalog.upsert(entry)
                if action == "created":
                    created += 1
                elif action == "updated":
                    updated += 1

            missing = self.repos.catalog.delete_untracked(
                key, {entry.fingerprint for entry in entries}
            )
            self.repos.catalog_syncs.finish(
                sync_id,
                status="ok",
                entries_fetched=len(entries),
                entries_created=created,
                entries_updated=updated,
                entries_missing=missing,
            )
            self.repos.audit.log(
                "catalog_synced",
                entity_type="catalog",
                entity_id=key,
                detail={
                    "fetched": len(entries),
                    "created": created,
                    "updated": updated,
                    "missing": missing,
                },
                actor=actor,
            )
            results.append(
                CatalogSync(
                    sync_id=sync_id,
                    category=key,
                    category_label=category.label,
                    started_at=started,
                    finished_at=utcnow(),
                    status="ok",
                    entries_fetched=len(entries),
                    entries_created=created,
                    entries_updated=updated,
                    entries_missing=missing,
                )
            )

        return results

    # ------------------------------------------------------------------ #
    def search(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        network: Optional[CatalogNetwork] = None,
        status: Optional[CatalogStatus] = None,
        tracked_only: bool = False,
        limit: int = 500,
    ) -> list[CatalogEntry]:
        return self.repos.catalog.list(
            category=category,
            query=query,
            network=str(network) if network else None,
            status=str(status) if status else None,
            tracked_only=tracked_only,
            limit=limit,
        )

    def match_terms(
        self, terms: Sequence[str], limit_per_term: int = 25
    ) -> list[tuple[str, CatalogEntry]]:
        """Verilen terimlerin (ör. müşteri markası) katalogdaki karşılıklarını arar."""
        matches: list[tuple[str, CatalogEntry]] = []
        seen: set[tuple[str, int]] = set()
        for raw_term in terms:
            term = str(raw_term or "").strip()
            if len(term) < 3:
                continue
            for entry in self.repos.catalog.list(query=term, limit=limit_per_term):
                marker = (term.casefold(), entry.entry_id or 0)
                if marker in seen:
                    continue
                seen.add(marker)
                matches.append((term, entry))
        return matches

    def monitored_terms(self) -> list[str]:
        """Tanımlı izlenen varlıklardan eşleştirme terimlerini üretir."""
        terms: list[str] = []
        seen: set[str] = set()
        for asset in self.repos.assets.list_all():
            value = str(asset.get("value") or "").strip()
            if not value:
                continue
            # Alan adlarında ilk etiketi de ara (ör. "spk.gov.tr" -> "spk").
            candidates = [value]
            if "." in value and not value[0].isdigit():
                candidates.append(value.split(".")[0])
            for candidate in candidates:
                folded = candidate.casefold()
                if len(candidate) >= 3 and folded not in seen:
                    seen.add(folded)
                    terms.append(candidate)
        return terms

    # ------------------------------------------------------------------ #
    def promote(self, entry: CatalogEntry, actor: str = "analyst") -> SourceConfig:
        """Katalog kaydını izlenebilir (izin bekleyen) bir kaynağa dönüştürür.

        Kaynak **kapalı** ve izin beyanı **yapılmamış** olarak oluşturulur;
        analist kullanım iznini onaylamadan hiçbir istek yapılmaz (PRD 9.6).
        """
        if not entry.url:
            raise ValueError("Bu katalog kaydının izlenecek bir adresi yok.")

        digest = hashlib.sha256(str(entry.url).encode("utf-8")).hexdigest()[:6]
        name = f"ddcti_{entry.category}_{_slug(entry.name)}"[:60].strip("_")
        name = f"{name}_{digest}"

        config = SourceConfig(
            name=name,
            adapter="darkweb_source",
            source_type=SourceType.DARKWEB_SOURCE,
            category=SourceCategory.AUTHORIZED_WEB,
            enabled=False,
            check_interval_minutes=720,
            reliability=0.4,
            settings={
                "url": entry.url,
                "api_key_env": "DARKWEB_SOURCE_API_KEY",
                "confirmed_authorized": False,
                "terms_reviewed": False,
                "catalog": {
                    "name": CATALOG_NAME,
                    "category": entry.category,
                    "entry": entry.name,
                },
            },
            notes=(
                f"deepdarkCTI kataloğundan izlemeye alındı ({entry.category_label}). "
                "Kaynağın kullanım izni ve koşulları onaylanmadan çalıştırılamaz."
            ),
        )
        self.repos.sources.upsert(config)
        if entry.entry_id is not None:
            self.repos.catalog.set_tracked(entry.entry_id, True, source_name=name)
        self.repos.audit.log(
            "catalog_entry_tracked",
            entity_type="source",
            entity_id=name,
            detail={
                "catalog": CATALOG_NAME,
                "category": entry.category,
                "entry": entry.name,
                "url": entry.url,
            },
            actor=actor,
        )
        return config

    # ------------------------------------------------------------------ #
    def stats(self) -> dict[str, Any]:
        data = dict(self.repos.catalog.stats())
        last = self.repos.catalog_syncs.last_success()
        data["last_success_at"] = last.finished_at if last else None
        data["category_count"] = len(DEEPDARK_CATEGORIES)
        return data


__all__ = [
    "CATALOG_NAME",
    "DEEPDARK_CATEGORIES",
    "CATEGORY_MAP",
    "CatalogCategory",
    "DeepDarkCatalogService",
    "MarkdownFetcher",
    "detect_network",
    "normalize_status",
    "normalize_column_key",
    "parse_catalog_entries",
    "parse_markdown_table",
    "split_table_row",
    "strip_markdown",
    "category_by_key",
    "category_label",
]
