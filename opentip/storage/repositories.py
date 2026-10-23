"""Depolama katmanı: repository sınıfları.

Repository'ler model nesneleri ile SQLite satırları arasındaki dönüşümü yapar.
Tüm modüller veritabanına yalnızca bu katman üzerinden erişir.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional, Sequence

from models import (
    Alert,
    AnalystNote,
    CatalogEntry,
    CatalogNetwork,
    CatalogStatus,
    CatalogSync,
    Evidence,
    Finding,
    FindingType,
    IOCRecord,
    IOCType,
    RiskLevel,
    RunStatus,
    SourceCategory,
    SourceConfig,
    SourceHealth,
    SourceRun,
    SourceStatus,
    SourceType,
    VerificationStatus,
    utcnow,
)
from .database import Database


# --------------------------------------------------------------------------- #
# Dönüşüm yardımcıları
# --------------------------------------------------------------------------- #
def _iso(value: datetime) -> str:
    return value.isoformat()


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _loads(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _enum(enum_cls, value, default):
    if value is None:
        return default
    try:
        return enum_cls(value)
    except ValueError:
        return default


# --------------------------------------------------------------------------- #
# Kurum profilleri ve varlıklar
# --------------------------------------------------------------------------- #
class OrganizationRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self,
        name: str,
        description: str = "",
        notifications_enabled: bool = True,
        settings: Optional[dict] = None,
    ) -> int:
        now = _iso(utcnow())
        return self.db.execute_insert(
            """INSERT INTO organizations(name, description, notifications_enabled, settings, created_at, updated_at)
               VALUES(?, ?, ?, ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET
                   description = excluded.description,
                   notifications_enabled = excluded.notifications_enabled,
                   settings = excluded.settings,
                   updated_at = excluded.updated_at""",
            (name, description, int(notifications_enabled), _dumps(settings or {}), now, now),
        )

    def get(self, organization_id: int) -> Optional[dict]:
        row = self.db.query_one("SELECT * FROM organizations WHERE id = ?", (organization_id,))
        return self._row_to_dict(row) if row else None

    def get_by_name(self, name: str) -> Optional[dict]:
        row = self.db.query_one("SELECT * FROM organizations WHERE name = ?", (name,))
        return self._row_to_dict(row) if row else None

    def list(self, include_assets: bool = True) -> list[dict]:
        rows = self.db.query("SELECT * FROM organizations ORDER BY name")
        result = [self._row_to_dict(r) for r in rows]
        if include_assets:
            for org in result:
                org["assets"] = AssetRepository(self.db).list_for_org(org["id"])
        return result

    def update(self, organization_id: int, **fields: Any) -> None:
        allowed = {"name", "description", "notifications_enabled", "settings"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        if "settings" in updates:
            updates["settings"] = _dumps(updates["settings"])
        if "notifications_enabled" in updates:
            updates["notifications_enabled"] = int(bool(updates["notifications_enabled"]))
        updates["updated_at"] = _iso(utcnow())
        assignments = ", ".join(f"{k} = ?" for k in updates)
        params: list[Any] = list(updates.values())
        params.append(organization_id)
        self.db.execute(f"UPDATE organizations SET {assignments} WHERE id = ?", tuple(params))

    def delete(self, organization_id: int) -> None:
        self.db.execute("DELETE FROM organizations WHERE id = ?", (organization_id,))

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["settings"] = _loads(data.get("settings"), {})
        data["notifications_enabled"] = bool(data.get("notifications_enabled"))
        return data


class AssetRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add(
        self,
        organization_id: int,
        asset_type: str,
        value: str,
        verified: bool = False,
    ) -> int:
        return self.db.execute_insert(
            """INSERT INTO monitored_assets(organization_id, asset_type, value, verified, created_at)
               VALUES(?, ?, ?, ?, ?)
               ON CONFLICT(organization_id, asset_type, value) DO UPDATE SET
                   verified = excluded.verified""",
            (organization_id, asset_type, value, int(verified), _iso(utcnow())),
        )

    def list_for_org(self, organization_id: int) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM monitored_assets WHERE organization_id = ? ORDER BY asset_type, value",
            (organization_id,),
        )
        return [dict(r) | {"verified": bool(r["verified"])} for r in rows]

    def list_all(self) -> list[dict]:
        rows = self.db.query("SELECT * FROM monitored_assets ORDER BY organization_id, asset_type")
        return [dict(r) | {"verified": bool(r["verified"])} for r in rows]

    def delete(self, asset_id: int) -> None:
        self.db.execute("DELETE FROM monitored_assets WHERE id = ?", (asset_id,))


# --------------------------------------------------------------------------- #
# Kaynaklar
# --------------------------------------------------------------------------- #
class SourceRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert(self, config: SourceConfig) -> int:
        now = _iso(utcnow())
        self.db.execute(
            """INSERT INTO sources(name, adapter, source_type, category, enabled,
                                   check_interval_minutes, reliability, settings, notes,
                                   created_at, updated_at)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET
                   adapter = excluded.adapter,
                   source_type = excluded.source_type,
                   category = excluded.category,
                   check_interval_minutes = excluded.check_interval_minutes,
                   reliability = excluded.reliability,
                   settings = excluded.settings,
                   notes = excluded.notes,
                   updated_at = excluded.updated_at""",
            (
                config.name,
                config.adapter,
                str(config.source_type),
                str(config.category),
                int(config.enabled),
                config.check_interval_minutes,
                config.reliability,
                _dumps(config.settings),
                config.notes,
                now,
                now,
            ),
        )
        row = self.db.query_one("SELECT id FROM sources WHERE name = ?", (config.name,))
        return int(row["id"]) if row else 0

    def get(self, name: str) -> Optional[SourceConfig]:
        row = self.db.query_one("SELECT * FROM sources WHERE name = ?", (name,))
        return self._row_to_config(row) if row else None

    def list(self, enabled_only: bool = False) -> list[SourceConfig]:
        sql = "SELECT * FROM sources"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY name"
        return [self._row_to_config(r) for r in self.db.query(sql)]

    def set_enabled(self, name: str, enabled: bool) -> None:
        self.db.execute(
            "UPDATE sources SET enabled = ?, updated_at = ? WHERE name = ?",
            (int(enabled), _iso(utcnow()), name),
        )

    def record_run_result(
        self,
        name: str,
        status: SourceStatus,
        message: str = "",
        success: Optional[bool] = None,
    ) -> None:
        """Kaynağın çalışma durumunu günceller.

        Başarısızlıkta `last_success_at` korunur (PRD 9.4).
        """
        now = _iso(utcnow())
        if success is True:
            self.db.execute(
                """UPDATE sources SET status = ?, status_message = ?, last_checked_at = ?,
                       last_success_at = ?, consecutive_failures = 0, updated_at = ?
                   WHERE name = ?""",
                (str(status), message, now, now, now, name),
            )
        else:
            self.db.execute(
                """UPDATE sources SET status = ?, status_message = ?, last_checked_at = ?,
                       last_error_at = ?, consecutive_failures = consecutive_failures + 1, updated_at = ?
                   WHERE name = ?""",
                (str(status), message, now, now, now, name),
            )

    def health(self, name: str) -> Optional[SourceHealth]:
        row = self.db.query_one("SELECT * FROM sources WHERE name = ?", (name,))
        if not row:
            return None
        return SourceHealth(
            source_name=row["name"],
            source_id=row["id"],
            status=_enum(SourceStatus, row["status"], SourceStatus.UNKNOWN),
            message=row["status_message"] or "",
            last_checked_at=_parse_dt(row["last_checked_at"]),
            last_success_at=_parse_dt(row["last_success_at"]),
            last_error_at=_parse_dt(row["last_error_at"]),
            consecutive_failures=row["consecutive_failures"] or 0,
            check_interval_minutes=row["check_interval_minutes"] or 60,
            enabled=bool(row["enabled"]),
        )

    def health_all(self) -> list[SourceHealth]:
        return [h for h in (self.health(c.name) for c in self.list()) if h is not None]

    @staticmethod
    def _row_to_config(row: sqlite3.Row) -> SourceConfig:
        return SourceConfig(
            source_id=row["id"],
            name=row["name"],
            adapter=row["adapter"],
            source_type=_enum(SourceType, row["source_type"], SourceType.IOC_FEED),
            category=_enum(SourceCategory, row["category"], SourceCategory.STRUCTURED_API),
            enabled=bool(row["enabled"]),
            check_interval_minutes=row["check_interval_minutes"] or 60,
            reliability=row["reliability"] if row["reliability"] is not None else 0.5,
            settings=_loads(row["settings"], {}),
            notes=row["notes"] or "",
        )


class SourceRunRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def start(self, source_name: str, source_id: Optional[int] = None, triggered_by: str = "manual") -> int:
        return self.db.execute_insert(
            """INSERT INTO source_runs(source_id, source_name, started_at, status, triggered_by)
               VALUES(?, ?, ?, ?, ?)""",
            (source_id, source_name, _iso(utcnow()), str(RunStatus.RUNNING), triggered_by),
        )

    def finish(
        self,
        run_id: int,
        status: RunStatus,
        records_fetched: int = 0,
        findings_created: int = 0,
        findings_updated: int = 0,
        error_message: Optional[str] = None,
    ) -> None:
        self.db.execute(
            """UPDATE source_runs SET finished_at = ?, status = ?, records_fetched = ?,
                   findings_created = ?, findings_updated = ?, error_message = ?
               WHERE id = ?""",
            (
                _iso(utcnow()),
                str(status),
                records_fetched,
                findings_created,
                findings_updated,
                error_message,
                run_id,
            ),
        )

    def list_recent(self, limit: int = 50, source_name: Optional[str] = None) -> list[SourceRun]:
        if source_name:
            rows = self.db.query(
                "SELECT * FROM source_runs WHERE source_name = ? ORDER BY started_at DESC LIMIT ?",
                (source_name, limit),
            )
        else:
            rows = self.db.query(
                "SELECT * FROM source_runs ORDER BY started_at DESC LIMIT ?", (limit,)
            )
        return [self._row_to_run(r) for r in rows]

    def last_run(self, source_name: str) -> Optional[SourceRun]:
        runs = self.list_recent(limit=1, source_name=source_name)
        return runs[0] if runs else None

    @staticmethod
    def _row_to_run(row: sqlite3.Row) -> SourceRun:
        return SourceRun(
            run_id=row["id"],
            source_id=row["source_id"],
            source_name=row["source_name"],
            started_at=_parse_dt(row["started_at"]) or utcnow(),
            finished_at=_parse_dt(row["finished_at"]),
            status=_enum(RunStatus, row["status"], RunStatus.RUNNING),
            records_fetched=row["records_fetched"] or 0,
            findings_created=row["findings_created"] or 0,
            findings_updated=row["findings_updated"] or 0,
            error_message=row["error_message"],
            triggered_by=row["triggered_by"] or "manual",
        )


# --------------------------------------------------------------------------- #
# IOC kayıtları
# --------------------------------------------------------------------------- #
class IOCRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert(self, record: IOCRecord) -> tuple[int, bool]:
        """Parmak izine göre ekler veya günceller. (id, created) döndürür."""
        if not record.fingerprint:
            raise ValueError("IOC kaydı için parmak izi zorunludur")
        existing = self.db.query_one(
            "SELECT id FROM ioc_records WHERE fingerprint = ?", (record.fingerprint,)
        )
        now = _iso(utcnow())
        if existing:
            self.db.execute(
                """UPDATE ioc_records SET last_seen = ?, risk_level = ?, confidence = ?, detail = ?
                   WHERE id = ?""",
                (
                    _iso(record.last_seen),
                    str(record.risk_level),
                    record.confidence,
                    _dumps(record.detail),
                    existing["id"],
                ),
            )
            return int(existing["id"]), False
        new_id = self.db.execute_insert(
            """INSERT INTO ioc_records(value, ioc_type, source_name, source_type, source_reference,
                                       first_seen, last_seen, tags, risk_level, confidence, detail,
                                       fingerprint, created_at)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.value,
                str(record.ioc_type),
                record.source_name,
                str(record.source_type),
                record.source_reference,
                _iso(record.first_seen),
                _iso(record.last_seen),
                _dumps(record.tags),
                str(record.risk_level),
                record.confidence,
                _dumps(record.detail),
                record.fingerprint,
                now,
            ),
        )
        return new_id, True

    def list(self, value: Optional[str] = None, limit: int = 200) -> list[dict]:
        if value:
            rows = self.db.query(
                "SELECT * FROM ioc_records WHERE value = ? ORDER BY last_seen DESC LIMIT ?",
                (value, limit),
            )
        else:
            rows = self.db.query(
                "SELECT * FROM ioc_records ORDER BY last_seen DESC LIMIT ?", (limit,)
            )
        return [self._row_to_dict(r) for r in rows]

    def recent(self, limit: int = 20) -> list[dict]:
        return self.list(limit=limit)

    def count(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS c FROM ioc_records")
        return int(row["c"]) if row else 0

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "value": row["value"],
            "ioc_type": _enum(IOCType, row["ioc_type"], IOCType.DOMAIN),
            "source_name": row["source_name"],
            "source_type": _enum(SourceType, row["source_type"], SourceType.IOC_FEED),
            "source_reference": row["source_reference"],
            "first_seen": _parse_dt(row["first_seen"]),
            "last_seen": _parse_dt(row["last_seen"]),
            "tags": _loads(row["tags"], []),
            "risk_level": _enum(RiskLevel, row["risk_level"], RiskLevel.UNASSESSED),
            "confidence": row["confidence"],
            "detail": _loads(row["detail"], {}),
        }


# --------------------------------------------------------------------------- #
# Bulgular
# --------------------------------------------------------------------------- #
FINDING_FIELDS = (
    "finding_id",
    "fingerprint",
    "finding_type",
    "organization_id",
    "organization",
    "matched_domain",
    "ioc_value",
    "ioc_type",
    "source_type",
    "source_name",
    "source_reference",
    "first_seen",
    "last_checked",
    "claimed_event_date",
    "claimed_data_types",
    "source_reliability",
    "verification_status",
    "risk_level",
    "risk_score",
    "risk_reasons",
    "evidence_summary",
    "notifications_sent",
    "metadata",
)


class FindingRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert(self, finding: Finding) -> tuple[Finding, bool, list[str]]:
        """Bulgu parmak izine göre ekler veya günceller.

        Dönen değer: (kaydedilmiş bulgu, yeni mi, değişen alanlar).
        Tekrarlanan kayıt yeni alarm üretmemelidir (PRD 9.5).
        """
        if not finding.fingerprint:
            raise ValueError("Bulgu için parmak izi zorunludur")
        now = _iso(utcnow())
        existing_row = self.db.query_one(
            "SELECT * FROM findings WHERE fingerprint = ?", (finding.fingerprint,)
        )

        if existing_row is None:
            self.db.execute(
                """INSERT INTO findings(
                       finding_id, fingerprint, finding_type, organization_id, organization,
                       matched_domain, ioc_value, ioc_type, source_type, source_name,
                       source_reference, first_seen, last_checked, claimed_event_date,
                       claimed_data_types, source_reliability, verification_status, risk_level,
                       risk_score, risk_reasons, evidence_summary, notifications_sent,
                       metadata, created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.finding_id,
                    finding.fingerprint,
                    str(finding.finding_type),
                    finding.organization_id,
                    finding.organization,
                    finding.matched_domain,
                    finding.ioc_value,
                    str(finding.ioc_type) if finding.ioc_type else None,
                    str(finding.source_type),
                    finding.source_name,
                    finding.source_reference,
                    _iso(finding.first_seen),
                    _iso(finding.last_checked),
                    _iso(finding.claimed_event_date) if finding.claimed_event_date else None,
                    _dumps(finding.claimed_data_types),
                    finding.source_reliability,
                    str(finding.verification_status),
                    str(finding.risk_level),
                    finding.risk_score,
                    _dumps(finding.risk_reasons),
                    finding.evidence_summary,
                    int(finding.notifications_sent),
                    _dumps(finding.metadata),
                    now,
                    now,
                ),
            )
            return finding, True, []

        existing = self._row_to_finding(existing_row)
        changes = self._diff(existing, finding)
        if not changes:
            # Yalnızca son kontrol zamanını güncelle.
            self.db.execute(
                "UPDATE findings SET last_checked = ?, updated_at = ? WHERE fingerprint = ?",
                (_iso(finding.last_checked), now, finding.fingerprint),
            )
            existing.last_checked = finding.last_checked
            return existing, False, []

        merged = existing.model_copy(
            update={
                "last_checked": finding.last_checked,
                "verification_status": finding.verification_status,
                "risk_level": finding.risk_level,
                "risk_score": finding.risk_score,
                "risk_reasons": finding.risk_reasons,
                "evidence_summary": finding.evidence_summary or existing.evidence_summary,
                "claimed_event_date": finding.claimed_event_date or existing.claimed_event_date,
                "claimed_data_types": finding.claimed_data_types or existing.claimed_data_types,
                "source_reliability": finding.source_reliability or existing.source_reliability,
                "metadata": {**existing.metadata, **finding.metadata},
            }
        )
        self.db.execute(
            """UPDATE findings SET last_checked = ?, verification_status = ?, risk_level = ?,
                   risk_score = ?, risk_reasons = ?, evidence_summary = ?, claimed_event_date = ?,
                   claimed_data_types = ?, source_reliability = ?, metadata = ?, updated_at = ?
               WHERE fingerprint = ?""",
            (
                _iso(merged.last_checked),
                str(merged.verification_status),
                str(merged.risk_level),
                merged.risk_score,
                _dumps(merged.risk_reasons),
                merged.evidence_summary,
                _iso(merged.claimed_event_date) if merged.claimed_event_date else None,
                _dumps(merged.claimed_data_types),
                merged.source_reliability,
                _dumps(merged.metadata),
                now,
                finding.fingerprint,
            ),
        )
        return merged, False, changes

    @staticmethod
    def _diff(existing: Finding, incoming: Finding) -> list[str]:
        changes: list[str] = []
        if str(existing.verification_status) != str(incoming.verification_status):
            changes.append("verification_status")
        if str(existing.risk_level) != str(incoming.risk_level):
            changes.append("risk_level")
        if sorted(existing.claimed_data_types) != sorted(incoming.claimed_data_types):
            changes.append("claimed_data_types")
        if (existing.evidence_summary or "") != (incoming.evidence_summary or ""):
            changes.append("evidence_summary")
        return changes

    def get(self, finding_id: str) -> Optional[Finding]:
        row = self.db.query_one("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
        return self._row_to_finding(row) if row else None

    def get_by_fingerprint(self, fingerprint: str) -> Optional[Finding]:
        row = self.db.query_one("SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,))
        return self._row_to_finding(row) if row else None

    def list(
        self,
        finding_type: Optional[FindingType] = None,
        verification_status: Optional[VerificationStatus] = None,
        risk_level: Optional[RiskLevel] = None,
        organization_id: Optional[int] = None,
        search: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[Finding]:
        clauses: list[str] = []
        params: list[Any] = []
        if finding_type:
            clauses.append("finding_type = ?")
            params.append(str(finding_type))
        if verification_status:
            clauses.append("verification_status = ?")
            params.append(str(verification_status))
        if risk_level:
            clauses.append("risk_level = ?")
            params.append(str(risk_level))
        if organization_id:
            clauses.append("organization_id = ?")
            params.append(organization_id)
        if search:
            clauses.append(
                "(organization LIKE ? OR matched_domain LIKE ? OR ioc_value LIKE ? "
                "OR evidence_summary LIKE ? OR source_reference LIKE ?)"
            )
            term = f"%{search}%"
            params.extend([term] * 5)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        rows = self.db.query(
            f"SELECT * FROM findings {where} ORDER BY last_checked DESC, id DESC LIMIT ? OFFSET ?",
            tuple(params),
        )
        return [self._row_to_finding(r) for r in rows]

    def count(self, **filters: Any) -> int:
        return len(self.list(**filters, limit=100000))

    def list_by_source(self, source_name: str, limit: int = 1000) -> list[Finding]:
        """Bir kaynağa ait bilinen tüm bulgular (değişiklik tespiti için)."""
        rows = self.db.query(
            "SELECT * FROM findings WHERE source_name = ? ORDER BY last_checked DESC LIMIT ?",
            (source_name, limit),
        )
        return [self._row_to_finding(r) for r in rows]

    def update_status(self, finding_id: str, status: VerificationStatus) -> None:
        self.db.execute(
            "UPDATE findings SET verification_status = ?, updated_at = ? WHERE finding_id = ?",
            (str(status), _iso(utcnow()), finding_id),
        )

    def update_risk(
        self, finding_id: str, risk_level: RiskLevel, score: Optional[float], reasons: Sequence[str]
    ) -> None:
        self.db.execute(
            """UPDATE findings SET risk_level = ?, risk_score = ?, risk_reasons = ?, updated_at = ?
               WHERE finding_id = ?""",
            (str(risk_level), score, _dumps(list(reasons)), _iso(utcnow()), finding_id),
        )

    def mark_notified(self, finding_id: str) -> None:
        self.db.execute(
            "UPDATE findings SET notifications_sent = 1, updated_at = ? WHERE finding_id = ?",
            (_iso(utcnow()), finding_id),
        )

    def set_organization(self, finding_id: str, organization_id: Optional[int], name: Optional[str]) -> None:
        self.db.execute(
            "UPDATE findings SET organization_id = ?, organization = ?, updated_at = ? WHERE finding_id = ?",
            (organization_id, name, _iso(utcnow()), finding_id),
        )

    def stats(self) -> dict[str, Any]:
        total = self.db.query_one("SELECT COUNT(*) AS c FROM findings")
        by_type = self.db.query(
            "SELECT finding_type, COUNT(*) AS c FROM findings GROUP BY finding_type"
        )
        by_status = self.db.query(
            "SELECT verification_status, COUNT(*) AS c FROM findings GROUP BY verification_status"
        )
        by_risk = self.db.query("SELECT risk_level, COUNT(*) AS c FROM findings GROUP BY risk_level")
        return {
            "total": int(total["c"]) if total else 0,
            "by_type": {r["finding_type"]: r["c"] for r in by_type},
            "by_status": {r["verification_status"]: r["c"] for r in by_status},
            "by_risk": {r["risk_level"]: r["c"] for r in by_risk},
        }

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding(
            finding_id=row["finding_id"],
            fingerprint=row["fingerprint"],
            finding_type=_enum(FindingType, row["finding_type"], FindingType.BREACH_CLAIM),
            organization_id=row["organization_id"],
            organization=row["organization"],
            matched_domain=row["matched_domain"],
            ioc_value=row["ioc_value"],
            ioc_type=_enum(IOCType, row["ioc_type"], None) if row["ioc_type"] else None,
            source_type=_enum(SourceType, row["source_type"], SourceType.IOC_FEED),
            source_name=row["source_name"],
            source_reference=row["source_reference"],
            first_seen=_parse_dt(row["first_seen"]) or utcnow(),
            last_checked=_parse_dt(row["last_checked"]) or utcnow(),
            claimed_event_date=_parse_dt(row["claimed_event_date"]),
            claimed_data_types=_loads(row["claimed_data_types"], []),
            source_reliability=row["source_reliability"],
            verification_status=_enum(
                VerificationStatus, row["verification_status"], VerificationStatus.NEW
            ),
            risk_level=_enum(RiskLevel, row["risk_level"], RiskLevel.UNASSESSED),
            risk_score=row["risk_score"],
            risk_reasons=_loads(row["risk_reasons"], []),
            evidence_summary=row["evidence_summary"] or "",
            notifications_sent=bool(row["notifications_sent"]),
            metadata=_loads(row["metadata"], {}),
        )


class EvidenceRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add(self, evidence: Evidence) -> int:
        return self.db.execute_insert(
            """INSERT INTO evidence(finding_id, source_name, source_type, source_reference,
                                    collected_at, summary, content_type, content_digest, confidence)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                evidence.finding_id,
                evidence.source_name,
                str(evidence.source_type),
                evidence.source_reference,
                _iso(evidence.collected_at),
                evidence.summary,
                evidence.content_type,
                evidence.content_digest,
                evidence.confidence,
            ),
        )

    def list_for_finding(self, finding_id: str) -> list[Evidence]:
        rows = self.db.query(
            "SELECT * FROM evidence WHERE finding_id = ? ORDER BY collected_at DESC", (finding_id,)
        )
        return [
            Evidence(
                evidence_id=r["id"],
                finding_id=r["finding_id"],
                source_name=r["source_name"],
                source_type=_enum(SourceType, r["source_type"], SourceType.BREACH_FEED),
                source_reference=r["source_reference"],
                collected_at=_parse_dt(r["collected_at"]) or utcnow(),
                summary=r["summary"] or "",
                content_type=r["content_type"] or "text/plain",
                content_digest=r["content_digest"],
                confidence=r["confidence"],
            )
            for r in rows
        ]


class AlertRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, alert: Alert) -> int:
        return self.db.execute_insert(
            """INSERT INTO alerts(alert_type, severity, finding_id, source_name, title, message,
                                  created_at, acknowledged)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.alert_type,
                str(alert.severity),
                alert.finding_id,
                alert.source_name,
                alert.title,
                alert.message,
                _iso(alert.created_at),
                int(alert.acknowledged),
            ),
        )

    def list(self, limit: int = 100, unacknowledged_only: bool = False) -> list[Alert]:
        sql = "SELECT * FROM alerts"
        if unacknowledged_only:
            sql += " WHERE acknowledged = 0"
        sql += " ORDER BY created_at DESC LIMIT ?"
        rows = self.db.query(sql, (limit,))
        return [
            Alert(
                alert_id=r["id"],
                alert_type=r["alert_type"],
                severity=_enum(RiskLevel, r["severity"], RiskLevel.UNASSESSED),
                finding_id=r["finding_id"],
                source_name=r["source_name"],
                title=r["title"] or "",
                message=r["message"] or "",
                created_at=_parse_dt(r["created_at"]) or utcnow(),
                acknowledged=bool(r["acknowledged"]),
            )
            for r in rows
        ]

    def acknowledge(self, alert_id: int) -> None:
        self.db.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))

    def acknowledge_all(self) -> None:
        self.db.execute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")

    def open_count(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS c FROM alerts WHERE acknowledged = 0")
        return int(row["c"]) if row else 0


class NoteRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add(self, finding_id: str, note: str, author: str = "analyst") -> int:
        return self.db.execute_insert(
            """INSERT INTO analyst_notes(finding_id, author, note, created_at) VALUES(?, ?, ?, ?)""",
            (finding_id, author, note, _iso(utcnow())),
        )

    def list_for_finding(self, finding_id: str) -> list[AnalystNote]:
        rows = self.db.query(
            "SELECT * FROM analyst_notes WHERE finding_id = ? ORDER BY created_at DESC", (finding_id,)
        )
        return [
            AnalystNote(
                note_id=r["id"],
                finding_id=r["finding_id"],
                author=r["author"],
                note=r["note"],
                created_at=_parse_dt(r["created_at"]) or utcnow(),
            )
            for r in rows
        ]


class AuditRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def log(
        self,
        action: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[Any] = None,
        detail: Optional[dict] = None,
        actor: str = "system",
    ) -> int:
        return self.db.execute_insert(
            """INSERT INTO audit_log(actor, action, entity_type, entity_id, detail, created_at)
               VALUES(?, ?, ?, ?, ?, ?)""",
            (
                actor,
                action,
                entity_type,
                str(entity_id) if entity_id is not None else None,
                _dumps(detail or {}),
                _iso(utcnow()),
            ),
        )

    def list(self, limit: int = 100) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM audit_log ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
        )
        return [
            {
                "id": r["id"],
                "actor": r["actor"],
                "action": r["action"],
                "entity_type": r["entity_type"],
                "entity_id": r["entity_id"],
                "detail": _loads(r["detail"], {}),
                "created_at": _parse_dt(r["created_at"]),
            }
            for r in rows
        ]


# --------------------------------------------------------------------------- #
# deepdarkCTI kaynak kataloğu
# --------------------------------------------------------------------------- #
class CatalogRepository:
    """deepdarkCTI katalog kayıtları. Bu kayıtlar bulgu değildir, referanstır."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert(self, entry: CatalogEntry) -> tuple[int, str]:
        """Kaydı parmak izine göre ekler/günceller. (id, eylem) döndürür.

        Eylem: "created" | "updated" | "unchanged".
        """
        fingerprint = entry.fingerprint
        now = _iso(utcnow())
        existing = self.db.query_one(
            "SELECT id, content_digest FROM catalog_entries WHERE fingerprint = ?",
            (fingerprint,),
        )
        if existing is None:
            new_id = self.db.execute_insert(
                """INSERT INTO catalog_entries(catalog, category, category_label, name, url,
                       network, status, description, columns, content_digest, tracked,
                       source_name, notes, first_synced_at, last_synced_at, fingerprint)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry.catalog,
                    entry.category,
                    entry.category_label,
                    entry.name,
                    entry.url,
                    str(entry.network),
                    str(entry.status),
                    entry.description,
                    _dumps(entry.columns),
                    entry.content_digest,
                    int(entry.tracked),
                    entry.source_name,
                    entry.notes,
                    now,
                    now,
                    fingerprint,
                ),
            )
            return new_id, "created"

        changed = (existing["content_digest"] or "") != entry.content_digest
        self.db.execute(
            """UPDATE catalog_entries SET category_label = ?, name = ?, url = ?, network = ?,
                   status = ?, description = ?, columns = ?, content_digest = ?, last_synced_at = ?
               WHERE id = ?""",
            (
                entry.category_label,
                entry.name,
                entry.url,
                str(entry.network),
                str(entry.status),
                entry.description,
                _dumps(entry.columns),
                entry.content_digest,
                now,
                existing["id"],
            ),
        )
        return int(existing["id"]), "updated" if changed else "unchanged"

    def get(self, entry_id: int) -> Optional[CatalogEntry]:
        row = self.db.query_one("SELECT * FROM catalog_entries WHERE id = ?", (entry_id,))
        return self._row_to_entry(row) if row else None

    def list(
        self,
        *,
        category: Optional[str] = None,
        query: Optional[str] = None,
        network: Optional[str] = None,
        status: Optional[str] = None,
        tracked_only: bool = False,
        limit: int = 500,
        offset: int = 0,
    ) -> list[CatalogEntry]:
        clauses: list[str] = []
        params: list[Any] = []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if network:
            clauses.append("network = ?")
            params.append(str(network))
        if status:
            clauses.append("status = ?")
            params.append(str(status))
        if tracked_only:
            clauses.append("tracked = 1")
        if query:
            clauses.append("(name LIKE ? OR url LIKE ? OR description LIKE ?)")
            term = f"%{query}%"
            params.extend([term, term, term])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        rows = self.db.query(
            f"SELECT * FROM catalog_entries {where} ORDER BY category, name LIMIT ? OFFSET ?",
            tuple(params),
        )
        return [self._row_to_entry(r) for r in rows]

    def fingerprints(self, category: str) -> set[str]:
        rows = self.db.query(
            "SELECT fingerprint, tracked FROM catalog_entries WHERE category = ?", (category,)
        )
        return {r["fingerprint"] for r in rows}

    def delete_untracked(self, category: str, keep_fingerprints: set[str]) -> int:
        """Kaynaktan kaldırılan ve izlenmeyen kayıtları siler.

        İzlemeye alınmış kayıtlar analist kararı olduğu için korunur.
        """
        rows = self.db.query(
            "SELECT id, fingerprint, tracked FROM catalog_entries WHERE category = ?", (category,)
        )
        removed = 0
        for row in rows:
            if row["fingerprint"] in keep_fingerprints or row["tracked"]:
                continue
            self.db.execute("DELETE FROM catalog_entries WHERE id = ?", (row["id"],))
            removed += 1
        return removed

    def set_tracked(
        self,
        entry_id: int,
        tracked: bool,
        source_name: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        current = self.get(entry_id)
        if current is None:
            return
        self.db.execute(
            "UPDATE catalog_entries SET tracked = ?, source_name = ?, notes = ? WHERE id = ?",
            (
                int(tracked),
                source_name if source_name is not None else current.source_name,
                notes if notes is not None else current.notes,
                entry_id,
            ),
        )

    def count(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS c FROM catalog_entries")
        return int(row["c"]) if row else 0

    def stats(self) -> dict[str, Any]:
        by_category = self.db.query(
            "SELECT category, COUNT(*) AS c FROM catalog_entries GROUP BY category ORDER BY category"
        )
        by_network = self.db.query(
            "SELECT network, COUNT(*) AS c FROM catalog_entries GROUP BY network"
        )
        by_status = self.db.query(
            "SELECT status, COUNT(*) AS c FROM catalog_entries GROUP BY status"
        )
        tracked = self.db.query_one(
            "SELECT COUNT(*) AS c FROM catalog_entries WHERE tracked = 1"
        )
        return {
            "total": self.count(),
            "tracked": int(tracked["c"]) if tracked else 0,
            "by_category": {r["category"]: r["c"] for r in by_category},
            "by_network": {r["network"]: r["c"] for r in by_network},
            "by_status": {r["status"]: r["c"] for r in by_status},
        }

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> CatalogEntry:
        return CatalogEntry(
            entry_id=row["id"],
            catalog=row["catalog"],
            category=row["category"],
            category_label=row["category_label"] or "",
            name=row["name"],
            url=row["url"],
            network=_enum(CatalogNetwork, row["network"], CatalogNetwork.UNKNOWN),
            status=_enum(CatalogStatus, row["status"], CatalogStatus.UNKNOWN),
            description=row["description"] or "",
            columns=_loads(row["columns"], {}),
            content_digest=row["content_digest"] or "",
            tracked=bool(row["tracked"]),
            source_name=row["source_name"],
            notes=row["notes"] or "",
            first_synced_at=_parse_dt(row["first_synced_at"]) or utcnow(),
            last_synced_at=_parse_dt(row["last_synced_at"]) or utcnow(),
        )


class CatalogSyncRepository:
    """Katalog eşitleme çalışmalarının kaydı."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def start(self, category: str, category_label: str = "", catalog: str = "deepdarkcti") -> int:
        return self.db.execute_insert(
            """INSERT INTO catalog_syncs(catalog, category, category_label, started_at, status)
               VALUES(?, ?, ?, ?, 'running')""",
            (catalog, category, category_label, _iso(utcnow())),
        )

    def finish(
        self,
        sync_id: int,
        *,
        status: str,
        entries_fetched: int = 0,
        entries_created: int = 0,
        entries_updated: int = 0,
        entries_missing: int = 0,
        error_message: Optional[str] = None,
    ) -> None:
        self.db.execute(
            """UPDATE catalog_syncs SET finished_at = ?, status = ?, entries_fetched = ?,
                   entries_created = ?, entries_updated = ?, entries_missing = ?, error_message = ?
               WHERE id = ?""",
            (
                _iso(utcnow()),
                status,
                entries_fetched,
                entries_created,
                entries_updated,
                entries_missing,
                error_message,
                sync_id,
            ),
        )

    def list_recent(self, limit: int = 40, category: Optional[str] = None) -> list[CatalogSync]:
        if category:
            rows = self.db.query(
                "SELECT * FROM catalog_syncs WHERE category = ? ORDER BY started_at DESC LIMIT ?",
                (category, limit),
            )
        else:
            rows = self.db.query(
                "SELECT * FROM catalog_syncs ORDER BY started_at DESC LIMIT ?", (limit,)
            )
        return [self._row_to_sync(r) for r in rows]

    def last_success(self, category: Optional[str] = None) -> Optional[CatalogSync]:
        if category:
            row = self.db.query_one(
                """SELECT * FROM catalog_syncs WHERE category = ? AND status = 'ok'
                   ORDER BY started_at DESC LIMIT 1""",
                (category,),
            )
        else:
            row = self.db.query_one(
                "SELECT * FROM catalog_syncs WHERE status = 'ok' ORDER BY started_at DESC LIMIT 1"
            )
        return self._row_to_sync(row) if row else None

    @staticmethod
    def _row_to_sync(row: sqlite3.Row) -> CatalogSync:
        return CatalogSync(
            sync_id=row["id"],
            catalog=row["catalog"],
            category=row["category"],
            category_label=row["category_label"] or "",
            started_at=_parse_dt(row["started_at"]) or utcnow(),
            finished_at=_parse_dt(row["finished_at"]),
            status=row["status"] or "running",
            entries_fetched=row["entries_fetched"] or 0,
            entries_created=row["entries_created"] or 0,
            entries_updated=row["entries_updated"] or 0,
            entries_missing=row["entries_missing"] or 0,
            error_message=row["error_message"],
        )


# --------------------------------------------------------------------------- #
# Repository kabı
# --------------------------------------------------------------------------- #
@dataclass
class Repositories:
    """Tüm repository'lere tek noktadan erişim."""

    db: Database
    organizations: OrganizationRepository = field(init=False)
    assets: AssetRepository = field(init=False)
    sources: SourceRepository = field(init=False)
    source_runs: SourceRunRepository = field(init=False)
    iocs: IOCRepository = field(init=False)
    findings: FindingRepository = field(init=False)
    evidence: EvidenceRepository = field(init=False)
    alerts: AlertRepository = field(init=False)
    notes: NoteRepository = field(init=False)
    audit: AuditRepository = field(init=False)
    catalog: CatalogRepository = field(init=False)
    catalog_syncs: CatalogSyncRepository = field(init=False)

    def __post_init__(self) -> None:
        self.organizations = OrganizationRepository(self.db)
        self.assets = AssetRepository(self.db)
        self.sources = SourceRepository(self.db)
        self.source_runs = SourceRunRepository(self.db)
        self.iocs = IOCRepository(self.db)
        self.findings = FindingRepository(self.db)
        self.evidence = EvidenceRepository(self.db)
        self.alerts = AlertRepository(self.db)
        self.notes = NoteRepository(self.db)
        self.audit = AuditRepository(self.db)
        self.catalog = CatalogRepository(self.db)
        self.catalog_syncs = CatalogSyncRepository(self.db)

    @classmethod
    def from_settings(cls, settings) -> "Repositories":
        db = Database(settings.database_file)
        db.initialize()
        return cls(db=db)
