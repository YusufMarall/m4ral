"""Değişiklik tespiti (PRD 9.5).

Sistem şu durumları ayırt eder:
* `new`       — daha önce görülmemiş kayıt
* `updated`   — bilinen kaydın önemli ölçüde değişmesi
* `unchanged` — aynı kaydın tekrar alınması (yeni alarm üretilmez)
* `missing`   — kaynakta artık bulunmayan kayıt
* `unchecked` — kaynak hatası nedeniyle kontrol edilemeyen kayıtlar
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

from models import ChangeType, Finding, FindingType
from storage import Repositories


@dataclass
class ChangeRecord:
    """Bir kayıt için tespit edilen değişiklik."""

    change_type: ChangeType
    fingerprint: str
    source_reference: Optional[str] = None
    finding_id: Optional[str] = None
    changed_fields: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class ChangeSummary:
    new: list[ChangeRecord] = field(default_factory=list)
    updated: list[ChangeRecord] = field(default_factory=list)
    unchanged: list[ChangeRecord] = field(default_factory=list)
    missing: list[ChangeRecord] = field(default_factory=list)
    unchecked: list[ChangeRecord] = field(default_factory=list)

    @property
    def totals(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "updated": len(self.updated),
            "unchanged": len(self.unchanged),
            "missing": len(self.missing),
            "unchecked": len(self.unchecked),
        }

    @property
    def actionable(self) -> list[ChangeRecord]:
        """Alarm/save gerektiren değişiklikler."""
        return self.new + self.updated


class ChangeDetector:
    """Getirilen kayıtları bilinen kayıtlarla karşılaştırır."""

    def __init__(self, repos: Repositories) -> None:
        self.repos = repos

    def known_fingerprints(self, source_name: str) -> dict[str, Finding]:
        return {f.fingerprint: f for f in self.repos.findings.list_by_source(source_name) if f.fingerprint}

    def classify(
        self,
        source_name: str,
        incoming: Sequence[Finding],
        source_ok: bool = True,
        finding_type: Optional[FindingType] = None,
    ) -> tuple[ChangeSummary, list[Finding]]:
        """Gelen kayıtları sınıflandırır.

        Dönen değer: (özet, kaydedilmesi gereken kayıtlar).
        `unchanged` kayıtlar kaydedilmez; yalnızca son kontrol zamanı güncellenir.
        """
        summary = ChangeSummary()
        known = self.known_fingerprints(source_name)

        # Aynı kaynak hem IOC hem sızıntı bulgusu üretebilir; yalnızca ilgili
        # bulgu türü karşılaştırılır.
        relevant_types = {f.finding_type for f in incoming}
        if not relevant_types and finding_type is not None:
            relevant_types = {finding_type}
        if relevant_types:
            known = {fp: f for fp, f in known.items() if f.finding_type in relevant_types}

        if not source_ok:
            for fingerprint, finding in known.items():
                summary.unchecked.append(
                    ChangeRecord(
                        change_type=ChangeType.UNCHECKED,
                        fingerprint=fingerprint,
                        source_reference=finding.source_reference,
                        finding_id=finding.finding_id,
                        reason="Kaynak hatası nedeniyle kontrol edilemedi.",
                    )
                )
            return summary, []

        seen: set[str] = set()
        to_save: list[Finding] = []

        for finding in incoming:
            fingerprint = finding.fingerprint or ""
            if not fingerprint:
                continue
            seen.add(fingerprint)
            existing = known.get(fingerprint)

            if existing is None:
                summary.new.append(
                    ChangeRecord(
                        change_type=ChangeType.NEW,
                        fingerprint=fingerprint,
                        source_reference=finding.source_reference,
                        reason="Daha önce görülmemiş kayıt.",
                    )
                )
                to_save.append(finding)
                continue

            changed = self._diff(existing, finding)
            if changed:
                finding.finding_id = existing.finding_id
                summary.updated.append(
                    ChangeRecord(
                        change_type=ChangeType.UPDATED,
                        fingerprint=fingerprint,
                        source_reference=finding.source_reference,
                        finding_id=existing.finding_id,
                        changed_fields=changed,
                        reason="Bilinen kayıtta önemli değişiklik: " + ", ".join(changed),
                    )
                )
                to_save.append(finding)
            else:
                summary.unchanged.append(
                    ChangeRecord(
                        change_type=ChangeType.UNCHANGED,
                        fingerprint=fingerprint,
                        source_reference=finding.source_reference,
                        finding_id=existing.finding_id,
                        reason="Aynı kayıt tekrar alındı; yeni alarm üretilmez.",
                    )
                )

        for fingerprint, existing in known.items():
            if fingerprint not in seen:
                summary.missing.append(
                    ChangeRecord(
                        change_type=ChangeType.MISSING,
                        fingerprint=fingerprint,
                        source_reference=existing.source_reference,
                        finding_id=existing.finding_id,
                        reason="Kayıt bu kontrolde kaynakta bulunamadı.",
                    )
                )

        return summary, to_save

    @staticmethod
    def _diff(existing: Finding, incoming: Finding) -> list[str]:
        """Yalnızca anlamlı değişiklikleri döndürür."""
        changes: list[str] = []
        if str(existing.risk_level) != str(incoming.risk_level):
            changes.append("risk_level")
        if sorted(existing.claimed_data_types) != sorted(incoming.claimed_data_types):
            changes.append("claimed_data_types")
        if (existing.evidence_summary or "").strip() != (incoming.evidence_summary or "").strip():
            changes.append("evidence_summary")
        if str(existing.verification_status) != str(incoming.verification_status):
            changes.append("verification_status")
        return changes
