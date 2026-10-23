"""SQLite veritabanı erişim katmanı.

Tasarım notları:
* Her işlem kendi bağlantısını açar; böylece Streamlit ve APScheduler
  iş parçacıkları arasında paylaşım sorunu oluşmaz.
* WAL modu eşzamanlı okuma/yazma için etkinleştirilir.
* Şema yalnızca gerekli asgari veriyi tutar; hassas sızıntı içerikleri saklanmaz.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional, Union

SCHEMA_VERSION = 2

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- İzlenen kurum profilleri (PRD 8.2)
CREATE TABLE IF NOT EXISTS organizations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    description   TEXT,
    notifications_enabled INTEGER NOT NULL DEFAULT 1,
    settings      TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- Kuruma ait izlenen varlıklar (domain, marka, takma ad, ...)
CREATE TABLE IF NOT EXISTS monitored_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_type      TEXT NOT NULL,
    value           TEXT NOT NULL,
    verified        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    UNIQUE (organization_id, asset_type, value)
);

-- Veri kaynaklarının yapılandırması (PRD 14)
CREATE TABLE IF NOT EXISTS sources (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    name                   TEXT NOT NULL UNIQUE,
    adapter                TEXT NOT NULL,
    source_type            TEXT NOT NULL,
    category               TEXT NOT NULL DEFAULT 'structured_api',
    enabled                INTEGER NOT NULL DEFAULT 1,
    check_interval_minutes INTEGER NOT NULL DEFAULT 60,
    reliability            REAL NOT NULL DEFAULT 0.5,
    settings               TEXT NOT NULL DEFAULT '{}',
    notes                  TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL DEFAULT 'unknown',
    status_message         TEXT NOT NULL DEFAULT '',
    last_checked_at        TEXT,
    last_success_at        TEXT,
    last_error_at          TEXT,
    consecutive_failures   INTEGER NOT NULL DEFAULT 0,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL
);

-- Kaynakların her kontrol çalışması
CREATE TABLE IF NOT EXISTS source_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id        INTEGER REFERENCES sources(id) ON DELETE SET NULL,
    source_name      TEXT NOT NULL,
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    status           TEXT NOT NULL DEFAULT 'running',
    records_fetched  INTEGER NOT NULL DEFAULT 0,
    findings_created INTEGER NOT NULL DEFAULT 0,
    findings_updated INTEGER NOT NULL DEFAULT 0,
    error_message    TEXT,
    triggered_by     TEXT NOT NULL DEFAULT 'manual'
);

-- IOC kayıtları (PRD 14)
CREATE TABLE IF NOT EXISTS ioc_records (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    value            TEXT NOT NULL,
    ioc_type         TEXT NOT NULL,
    source_name      TEXT NOT NULL,
    source_type      TEXT NOT NULL DEFAULT 'ioc_feed',
    source_reference TEXT,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    tags             TEXT NOT NULL DEFAULT '[]',
    risk_level       TEXT NOT NULL DEFAULT 'unassessed',
    confidence       REAL,
    detail           TEXT NOT NULL DEFAULT '{}',
    fingerprint      TEXT NOT NULL UNIQUE,
    created_at       TEXT NOT NULL
);

-- IOC ve sızıntı bulguları (ortak tablo)
CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id          TEXT NOT NULL UNIQUE,
    fingerprint         TEXT NOT NULL UNIQUE,
    finding_type        TEXT NOT NULL,
    organization_id     INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    organization        TEXT,
    matched_domain      TEXT,
    ioc_value           TEXT,
    ioc_type            TEXT,
    source_type         TEXT NOT NULL,
    source_name         TEXT NOT NULL,
    source_reference    TEXT,
    first_seen          TEXT NOT NULL,
    last_checked        TEXT NOT NULL,
    claimed_event_date  TEXT,
    claimed_data_types  TEXT NOT NULL DEFAULT '[]',
    source_reliability  REAL,
    verification_status TEXT NOT NULL DEFAULT 'new',
    risk_level          TEXT NOT NULL DEFAULT 'unassessed',
    risk_score          REAL,
    risk_reasons        TEXT NOT NULL DEFAULT '[]',
    evidence_summary    TEXT NOT NULL DEFAULT '',
    notifications_sent  INTEGER NOT NULL DEFAULT 0,
    metadata            TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

-- Kaynak referansları ve kanıt özetleri
CREATE TABLE IF NOT EXISTS evidence (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id       TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    source_name      TEXT NOT NULL,
    source_type      TEXT NOT NULL,
    source_reference TEXT,
    collected_at     TEXT NOT NULL,
    summary          TEXT NOT NULL DEFAULT '',
    content_type     TEXT NOT NULL DEFAULT 'text/plain',
    content_digest   TEXT,
    confidence       REAL
);

-- Uygulama içi alarmlar (PRD 12)
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type   TEXT NOT NULL,
    severity     TEXT NOT NULL DEFAULT 'unassessed',
    finding_id   TEXT,
    source_name  TEXT,
    title        TEXT NOT NULL DEFAULT '',
    message      TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

-- Analist notları
CREATE TABLE IF NOT EXISTS analyst_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    author     TEXT NOT NULL DEFAULT 'analyst',
    note       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Denetim kayıtları (PRD 16)
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor       TEXT NOT NULL DEFAULT 'system',
    action      TEXT NOT NULL,
    entity_type TEXT,
    entity_id   TEXT,
    detail      TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);

-- deepdarkCTI kaynak kataloğu kayıtları.
-- Katalog bir referans katmanıdır; buradaki kayıtlar bulgu üretmez.
CREATE TABLE IF NOT EXISTS catalog_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    catalog         TEXT NOT NULL DEFAULT 'deepdarkcti',
    category        TEXT NOT NULL,
    category_label  TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL,
    url             TEXT,
    network         TEXT NOT NULL DEFAULT 'unknown',
    status          TEXT NOT NULL DEFAULT 'unknown',
    description     TEXT NOT NULL DEFAULT '',
    columns         TEXT NOT NULL DEFAULT '{}',
    content_digest  TEXT NOT NULL DEFAULT '',
    tracked         INTEGER NOT NULL DEFAULT 0,
    source_name     TEXT,
    notes           TEXT NOT NULL DEFAULT '',
    first_synced_at TEXT NOT NULL,
    last_synced_at  TEXT NOT NULL,
    fingerprint     TEXT NOT NULL UNIQUE
);

-- Katalog eşitleme çalışmalarının kaydı
CREATE TABLE IF NOT EXISTS catalog_syncs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    catalog         TEXT NOT NULL DEFAULT 'deepdarkcti',
    category        TEXT NOT NULL,
    category_label  TEXT NOT NULL DEFAULT '',
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL DEFAULT 'running',
    entries_fetched INTEGER NOT NULL DEFAULT 0,
    entries_created INTEGER NOT NULL DEFAULT 0,
    entries_updated INTEGER NOT NULL DEFAULT 0,
    entries_missing INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_ioc_value      ON ioc_records(value);
CREATE INDEX IF NOT EXISTS idx_ioc_last_seen  ON ioc_records(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_find_type      ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_find_status    ON findings(verification_status);
CREATE INDEX IF NOT EXISTS idx_find_org       ON findings(organization_id);
CREATE INDEX IF NOT EXISTS idx_find_last      ON findings(last_checked DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_find  ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_notes_find     ON analyst_notes(finding_id);
CREATE INDEX IF NOT EXISTS idx_runs_source    ON source_runs(source_name, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_ack     ON alerts(acknowledged, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_catalog_cat    ON catalog_entries(category);
CREATE INDEX IF NOT EXISTS idx_catalog_name   ON catalog_entries(name);
CREATE INDEX IF NOT EXISTS idx_catalog_track  ON catalog_entries(tracked);
CREATE INDEX IF NOT EXISTS idx_csync_time     ON catalog_syncs(started_at DESC);
"""


class Database:
    """SQLite veritabanı erişimi."""

    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path).expanduser()
        self._initialized = False

    # ------------------------------------------------------------------ #
    # Bağlantı yönetimi
    # ------------------------------------------------------------------ #
    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yeni bir bağlantı açar, işlemi tamamlar ve kapatır."""
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path), timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        """Şemayı oluşturur (yoksa)."""
        with self.connect() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.execute(
                "INSERT INTO schema_meta(key, value) VALUES('version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )
        self._initialized = True

    def ensure_initialized(self) -> None:
        if not self._initialized:
            self.initialize()

    # ------------------------------------------------------------------ #
    # Yardımcı sorgular
    # ------------------------------------------------------------------ #
    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return list(conn.execute(sql, params).fetchall())

    def query_one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(sql, params).fetchone()

    def execute(self, sql: str, params: tuple = ()) -> None:
        with self.connect() as conn:
            conn.execute(sql, params)

    def execute_insert(self, sql: str, params: tuple = ()) -> int:
        with self.connect() as conn:
            cursor = conn.execute(sql, params)
            return int(cursor.lastrowid or 0)
