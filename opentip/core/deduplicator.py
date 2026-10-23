"""Parmak izi üretimi ve bulgu tekilleştirme (PRD 9.5).

Amaç: aynı kaydın tekrar alınması yeni alarm üretmemelidir; yalnızca
önemli değişikliklerde yeniden alarm oluşturulmalıdır.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Optional

from models import Finding, IOCRecord, RiskLevel

_RISK_ORDER = {
    RiskLevel.UNASSESSED: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def fingerprint(*parts: object) -> str:
    """Verilen parçalardan deterministik, kısa bir parmak izi üretir."""
    material = "|".join("" if p is None else str(p).strip().lower() for p in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:40]


def ioc_fingerprint(record: IOCRecord) -> str:
    """IOC kaydını (değer, tür, kaynak) üçlüsüne göre tanımlar."""
    return fingerprint("ioc", record.ioc_type, record.value, record.source_name)


def finding_fingerprint(finding: Finding) -> str:
    """Bulgu kimliğini; tür, ilişkilendirilen hedef ve kaynak referansına göre üretir.

    Kaynak referansı yoksa kanıt özeti de kimliğe dahil edilir.
    """
    target = (
        finding.organization
        or finding.matched_domain
        or finding.ioc_value
        or "unknown-target"
    )
    reference = finding.source_reference or finding.evidence_summary[:120] or "no-reference"
    return fingerprint("finding", finding.finding_type, target, finding.source_name, reference)


def deduplicate_records(records: Iterable[IOCRecord]) -> list[IOCRecord]:
    """Aynı göstergeyi farklı kaynaklardan birleştirir.

    Birleştirme kuralları:
    * En erken `first_seen`, en geç `last_seen` korunur.
    * Etiketler birleştirilir.
    * En yüksek risk seviyesi ve en yüksek güven değeri tutulur.
    * Tüm kaynak referansları `detail["sources"]` altında saklanır (kaynak şeffaflığı).
    """
    merged: dict[tuple[str, str], IOCRecord] = {}
    for record in records:
        key = (str(record.ioc_type), record.value)
        current = merged.get(key)
        if current is None:
            copy = record.model_copy(deep=True)
            copy.detail = dict(copy.detail)
            copy.detail["sources"] = [
                {"source_name": record.source_name, "source_reference": record.source_reference}
            ]
            merged[key] = copy
            continue

        sources = current.detail.setdefault("sources", [])
        entry = {"source_name": record.source_name, "source_reference": record.source_reference}
        if entry not in sources:
            sources.append(entry)

        current.first_seen = min(current.first_seen, record.first_seen)
        current.last_seen = max(current.last_seen, record.last_seen)
        current.tags = sorted(set(current.tags) | set(record.tags))
        if _RISK_ORDER.get(record.risk_level, 0) > _RISK_ORDER.get(current.risk_level, 0):
            current.risk_level = record.risk_level
        if record.confidence is not None:
            current.confidence = max(current.confidence or 0.0, record.confidence)

    return sorted(merged.values(), key=lambda r: (r.value, str(r.ioc_type)))


def merge_source_references(existing: Optional[dict], new_entries: list[dict]) -> dict:
    """`detail` sözlüğündeki kaynak listesini kayıpsız biçimde birleştirir."""
    detail = dict(existing or {})
    sources = list(detail.get("sources") or [])
    for entry in new_entries:
        if entry not in sources:
            sources.append(entry)
    detail["sources"] = sources
    return detail
