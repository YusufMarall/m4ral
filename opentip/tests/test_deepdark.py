"""deepdarkCTI katalog katmanı testleri (ayrıştırma, depolama, servis).

Testler gerçek ağ erişimi yapmaz; indirme katmanı sahte oturum veya sahte
indirici (stub) üzerinden yürütülür (PRD Bölüm 17).
"""

from __future__ import annotations

import pytest

from adapters.deepdarkcti import DeepDarkCTIAdapter, build_deepdarkcti_adapter
from core.deepdark import (
    CATEGORY_MAP,
    DeepDarkCatalogService,
    detect_network,
    normalize_column_key,
    normalize_status,
    parse_catalog_entries,
    parse_markdown_table,
    split_table_row,
    strip_markdown,
)
from models import CatalogNetwork, CatalogStatus, SourceConfig, SourceType

FORUM_MARKDOWN = """|Name|Status|Description|
| ------ | ------ | ------ |
|[0x00sec](https://0x00sec.org/)| ONLINE|
|[AGAINSTTHEWEST](http://giphvoitymatg4cv7bxqh5dz6sn6bfscywoat4qtslztkomf5lavrayd.onion) | OFFLINE | |
|[ALPHV Forum](https://alphv.pro) | ONLINE | Karting tartışmaları |
|[BHF](https://bhf.im)| OFFLINE ||
|[BHF](https://bhf.im)| ONLINE ||
"""

GANG_MARKDOWN = """|Name|Status|User:Password|Tox ID or other channel|RSS Feed|
| ------ | ------ | ------ | ------ | ------ |
|[8BASE](http://92.118.36.204)|ONLINE||https://t.me/eightbase - https://twitter.com/8BASEHOME||
|[54bb47h](http://54bb47h.blog)|OFFLINE||||
|[Sahipsiz kayit](http://example-onion.onion)|OFFLINE||||
"""


# --------------------------------------------------------------------------- #
# Ayrıştırma yardımcıları
# --------------------------------------------------------------------------- #
def test_split_table_row_pads_and_handles_pipes():
    assert split_table_row("|a|b||c||") == ["a", "b", "", "c", ""]
    assert split_table_row("|[0x00sec](https://x)| ONLINE|") == [
        "[0x00sec](https://x)",
        "ONLINE",
    ]
    assert split_table_row(r"|A\|B|x|") == ["A|B", "x"]


def test_normalize_column_key_and_strip_markdown():
    assert normalize_column_key("Tox ID or other channel") == "tox_id_or_other_channel"
    assert normalize_column_key("User:Password") == "user_password"
    assert strip_markdown("[8BASE](http://x)") == "8BASE"


def test_detect_network():
    assert detect_network("http://abc.onion") == CatalogNetwork.TOR
    assert detect_network("https://example.com") == CatalogNetwork.CLEARNET
    assert detect_network("http://92.118.36.204") == CatalogNetwork.CLEARNET
    assert detect_network(None) == CatalogNetwork.UNKNOWN


def test_normalize_status():
    assert normalize_status("ONLINE") == CatalogStatus.ONLINE
    assert normalize_status(" OFFLINE ") == CatalogStatus.OFFLINE
    assert normalize_status("") == CatalogStatus.UNKNOWN


def test_parse_markdown_table_finds_header_and_skips_separator():
    header, rows = parse_markdown_table(FORUM_MARKDOWN)
    assert header == ["Name", "Status", "Description"]
    assert len(rows) == 5
    assert rows[0][0] == "[0x00sec](https://0x00sec.org/)"


# --------------------------------------------------------------------------- #
# Katalog kaydı üretimi
# --------------------------------------------------------------------------- #
def test_parse_forum_entries():
    category = CATEGORY_MAP["forum"]
    entries = parse_catalog_entries(FORUM_MARKDOWN, category)

    # Aynı isim + URL iki kez geçen "BHF" tekilleştirilir.
    names = sorted(e.name for e in entries)
    assert names == ["0x00sec", "AGAINSTTHEWEST", "ALPHV Forum", "BHF"]

    tor_entry = next(e for e in entries if e.name == "AGAINSTTHEWEST")
    assert tor_entry.network == CatalogNetwork.TOR
    assert tor_entry.url.endswith(".onion")
    assert tor_entry.status == CatalogStatus.OFFLINE

    alphv = next(e for e in entries if e.name == "ALPHV Forum")
    assert alphv.category == "forum"
    assert alphv.description == "Karting tartışmaları"
    assert alphv.content_digest


def test_parse_gang_entries_keeps_extra_columns():
    category = CATEGORY_MAP["ransomware_gang"]
    entries = parse_catalog_entries(GANG_MARKDOWN, category)
    assert len(entries) == 3

    eight_base = next(e for e in entries if e.name == "8BASE")
    assert eight_base.network == CatalogNetwork.CLEARNET
    assert eight_base.status == CatalogStatus.ONLINE
    assert "https://t.me/eightbase" in eight_base.columns["tox_id_or_other_channel"]
    # Ayırıcı/durum sütunları ek sütun sözlüğüne yazılmaz.
    assert "status" not in eight_base.columns
    assert "name" not in eight_base.columns

    onion_entry = next(e for e in entries if e.name == "Sahipsiz kayit")
    assert onion_entry.network == CatalogNetwork.TOR
    assert onion_entry.columns == {}


def test_fingerprint_is_stable_and_distinguishes_urls():
    category = CATEGORY_MAP["forum"]
    first = parse_catalog_entries(FORUM_MARKDOWN, category)
    second = parse_catalog_entries(FORUM_MARKDOWN, category)
    assert {e.fingerprint for e in first} == {e.fingerprint for e in second}


# --------------------------------------------------------------------------- #
# Depolama
# --------------------------------------------------------------------------- #
def test_catalog_repository_upsert_and_filters(repos):
    category = CATEGORY_MAP["forum"]
    entries = parse_catalog_entries(FORUM_MARKDOWN, category)

    actions = [repos.catalog.upsert(entry)[1] for entry in entries]
    assert actions == ["created"] * len(entries)
    assert repos.catalog.count() == len(entries)

    # Aynı içerik tekrar eşitlenirse "unchanged" olur.
    assert repos.catalog.upsert(entries[0])[1] == "unchanged"

    # İçerik değişirse "updated" olur.
    changed = entries[0].model_copy(update={"status": CatalogStatus.OFFLINE, "content_digest": "farkli"})
    assert repos.catalog.upsert(changed)[1] == "updated"

    tor_only = repos.catalog.list(network=str(CatalogNetwork.TOR))
    assert [e.name for e in tor_only] == ["AGAINSTTHEWEST"]

    assert [e.name for e in repos.catalog.list(query="alphv")] == ["ALPHV Forum"]


def test_delete_untracked_keeps_tracked_entries(repos):
    category = CATEGORY_MAP["forum"]
    entries = parse_catalog_entries(FORUM_MARKDOWN, category)
    for entry in entries:
        repos.catalog.upsert(entry)

    kept = next(e for e in entries if e.name == "BHF")
    stored = repos.catalog.list(query="0x00sec")[0]
    repos.catalog.set_tracked(stored.entry_id, True, source_name="ddcti_test")

    # İzlenen kayıt (0x00sec) ve kataloğa göre hâlâ mevcut kayıt (BHF) korunur;
    # kalanlar kaynaktan kalkmış sayılır.
    removed = repos.catalog.delete_untracked("forum", {kept.fingerprint})
    assert removed == len(entries) - 2
    remaining = repos.catalog.list()
    assert sorted(e.name for e in remaining) == ["0x00sec", "BHF"]

    tracked = repos.catalog.list(tracked_only=True)
    assert [e.source_name for e in tracked] == ["ddcti_test"]


def test_catalog_stats(repos):
    for entry in parse_catalog_entries(FORUM_MARKDOWN, CATEGORY_MAP["forum"]):
        repos.catalog.upsert(entry)

    stats = repos.catalog.stats()
    assert stats["total"] == 4
    assert stats["by_network"]["clearnet"] == 3
    assert stats["by_network"]["tor"] == 1
    assert stats["tracked"] == 0


# --------------------------------------------------------------------------- #
# Servis
# --------------------------------------------------------------------------- #
class StubFetcher:
    """`MarkdownFetcher` yerine kullanılan basit sahte indirici."""

    def __init__(self, pages: dict[str, str] | None = None, error: str | None = None) -> None:
        self.pages = pages or {}
        self.error = error
        self.calls: list[str] = []

    def fetch_markdown(self, path: str) -> str:
        self.calls.append(path)
        if self.error:
            raise RuntimeError(self.error)
        return self.pages.get(path, "")

    def check_connection(self) -> bool:
        return self.error is None


@pytest.fixture
def catalog_service(repos):
    fetcher = StubFetcher({"forum.md": FORUM_MARKDOWN, "ransomware_gang.md": GANG_MARKDOWN})
    return DeepDarkCatalogService(repos, fetcher)


def test_sync_creates_then_keeps_entries_stable(catalog_service, repos):
    first = catalog_service.sync(["forum"])
    assert len(first) == 1
    assert first[0].status == "ok"
    assert first[0].entries_fetched == 4
    assert first[0].entries_created == 4
    assert repos.catalog.count() == 4

    second = catalog_service.sync(["forum"])
    assert second[0].entries_created == 0
    assert second[0].entries_updated == 0
    assert second[0].entries_missing == 0
    assert repos.catalog.count() == 4


def test_sync_records_failure_without_crashing(repos):
    service = DeepDarkCatalogService(repos, StubFetcher(error="depo erişilemedi"))
    outcome = service.sync(["forum"])

    assert outcome[0].status == "failed"
    assert "erişilemedi" in (outcome[0].error_message or "")
    assert repos.catalog.count() == 0
    assert repos.catalog_syncs.last_success() is None

    audit = repos.audit.list(limit=5)
    assert any(row["action"] == "catalog_sync_failed" for row in audit)


def test_sync_removes_dropped_entries(catalog_service, repos, settings):
    catalog_service.sync(["forum"])
    assert repos.catalog.count() == 4

    # Kaynakta yalnızca tek bir kayıt kaldı.
    catalog_service.fetcher.pages["forum.md"] = (
        "|Name|Status|Description|\n| --- | --- | --- |\n|[0x00sec](https://0x00sec.org/)| ONLINE|\n"
    )
    outcome = catalog_service.sync(["forum"])

    assert outcome[0].entries_missing == 3
    assert [e.name for e in repos.catalog.list()] == ["0x00sec"]


def test_match_terms_and_monitored_terms(catalog_service, repos):
    catalog_service.sync(["forum", "ransomware_gang"])
    org_id = repos.organizations.create("Nesil")
    repos.assets.add(org_id, "domain", "spk.gov.tr")
    repos.assets.add(org_id, "brand", "ALPHV")

    terms = catalog_service.monitored_terms()
    assert "spk.gov.tr" in terms
    assert "spk" in terms
    assert "ALPHV" in terms

    matches = catalog_service.match_terms(["ALPHV", "spk"])
    assert [entry.name for _term, entry in matches] == ["ALPHV Forum"]


def test_promote_creates_disabled_source_and_marks_entry(catalog_service, repos):
    catalog_service.sync(["forum"])
    entry = next(e for e in repos.catalog.list() if e.name == "0x00sec")

    config = catalog_service.promote(entry)

    assert config.adapter == "darkweb_source"
    assert config.source_type == SourceType.DARKWEB_SOURCE
    assert config.enabled is False
    assert config.settings["url"] == "https://0x00sec.org/"
    assert config.settings["confirmed_authorized"] is False
    assert config.settings["terms_reviewed"] is False

    stored = repos.sources.get(config.name)
    assert stored is not None
    assert stored.settings["url"] == "https://0x00sec.org/"

    refreshed = repos.catalog.get(entry.entry_id)
    assert refreshed is not None and refreshed.tracked is True
    assert refreshed.source_name == config.name

    assert any(
        row["action"] == "catalog_entry_tracked" for row in repos.audit.list(limit=10)
    )


def test_promote_without_url_is_rejected(catalog_service, repos):
    entry = parse_catalog_entries(
        "|Name|Status|\n| --- | --- |\n|Duzyazi kayit|ONLINE|\n", CATEGORY_MAP["forum"]
    )[0]
    repos.catalog.upsert(entry)
    stored = repos.catalog.list()[0]

    with pytest.raises(ValueError):
        catalog_service.promote(stored)


def test_service_stats_report_last_success(catalog_service):
    catalog_service.sync(["forum"])
    stats = catalog_service.stats()

    assert stats["total"] == 4
    assert stats["category_count"] == len(CATEGORY_MAP)
    assert stats["last_success_at"] is not None


# --------------------------------------------------------------------------- #
# HTTP istemcisi
# --------------------------------------------------------------------------- #
def test_adapter_fetches_markdown(settings, make_session, make_response):
    session = make_session([make_response(text=FORUM_MARKDOWN)])
    config = build_deepdarkcti_adapter(settings).source_config
    adapter = DeepDarkCTIAdapter(config, settings, session=session)

    text = adapter.fetch_markdown("forum.md")

    assert text == FORUM_MARKDOWN
    called = session.calls[0]
    assert called["method"] == "GET"
    assert called["url"].endswith("/deepdarkCTI/main/forum.md")
    # Bilinmeyen bağlantı takip edilmez.
    assert called["kwargs"]["allow_redirects"] is False


def test_adapter_rejects_path_traversal(settings, make_session):
    adapter = DeepDarkCTIAdapter(
        build_deepdarkcti_adapter(settings).source_config, settings, session=make_session([])
    )
    with pytest.raises(Exception):
        adapter.fetch_markdown("../../etc/passwd")


def test_adapter_check_connection(settings, make_session, make_response):
    session = make_session([make_response(text="# deepdarkCTI")])
    adapter = DeepDarkCTIAdapter(
        build_deepdarkcti_adapter(settings).source_config, settings, session=session
    )
    assert adapter.check_connection() is True


def test_build_adapter_uses_configured_base_url(settings):
    adapter = build_deepdarkcti_adapter(settings)
    assert adapter.adapter_name == "deepdarkcti"
    assert adapter.base_url == settings.deepdarkcti_base_url
    assert adapter.capabilities == {"connection_check"}


def test_adapter_config_requires_base_url(settings):
    config = SourceConfig(
        name="katalog",
        adapter="deepdarkcti",
        source_type=SourceType.DARKWEB_SOURCE,
        settings={},
    )
    adapter = DeepDarkCTIAdapter(config, settings)
    with pytest.raises(Exception):
        _ = adapter.base_url
