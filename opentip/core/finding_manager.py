"""Bulgu yaşam döngüsü yönetimi (PRD 8.4, 8.5, 8.6).

Sorumluluklar:
* Bulgu kimliği ve parmak izi üretmek.
* Kurum profilleriyle ilişkilendirme yapmak ve gerekçeleri saklamak.
* Risk değerlendirmesini çalıştırmak.
* Doğrulama durumu geçişlerini kurallara bağlı biçimde uygulamak.
* Tekrarlanan kayıtlarda gereksiz alarm üretmemek (PRD 9.5).
"""

from __future__ import annotations

import uuid
from typing import Any, Optional, Sequence

from pydantic import BaseModel, Field

from models import (
    AnalystNote,
    Evidence,
    Finding,
    FindingType,
    RiskLevel,
    SourceType,
    VerificationStatus,
    can_transition,
    utcnow,
)
from storage import Repositories
from .deduplicator import finding_fingerprint
from .risk_engine import RiskEngine


class NullNotifier:
    """Alarm üretmeyen varsayılan bildirim nesnesi."""

    def on_new_finding(self, finding: Finding) -> None:  # pragma: no cover - no-op
        ...

    def on_finding_changed(self, finding: Finding, changed_fields: Sequence[str]) -> None:  # pragma: no cover
        ...

    def on_status_change(
        self, finding: Finding, previous: VerificationStatus, current: VerificationStatus
    ) -> None:  # pragma: no cover
        ...

    def on_source_error(self, source_name: str, message: str) -> None:  # pragma: no cover
        ...

    def on_source_recovered(self, source_name: str) -> None:  # pragma: no cover
        ...


class FindingOutcome(BaseModel):
    """Bulgu kaydetme işleminin sonucu."""

    finding: Finding
    created: bool = False
    changed_fields: list[str] = Field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.changed_fields)


class FindingManager:
    def __init__(
        self,
        repos: Repositories,
        risk_engine: Optional[RiskEngine] = None,
        notifier: Optional[Any] = None,
    ) -> None:
        self.repos = repos
        self.risk_engine = risk_engine or RiskEngine()
        self.notifier = notifier or NullNotifier()

    # ------------------------------------------------------------------ #
    # Kimlik ve ilişkilendirme
    # ------------------------------------------------------------------ #
    @staticmethod
    def new_finding_id() -> str:
        return f"F-{uuid.uuid4().hex[:12].upper()}"

    def match_organization(
        self, *, domain: Optional[str] = None, text: str = "", explicit_name: Optional[str] = None
    ) -> tuple[Optional[dict], list[str]]:
        """Bulgu ile kurum profili arasında ilişki kurar ve gerekçeleri döndürür.

        Yalnızca isim/marka benzerliği zayıf bir ilişkidir ve doğrulanmış
        sayılmaz (PRD 8.2, 8.3).
        """
        if explicit_name:
            org = self.repos.organizations.get_by_name(explicit_name)
            if org:
                return org, [f"Analist tarafından doğrudan atandı: {explicit_name}"]

        organizations = self.repos.organizations.list(include_assets=True)
        if not organizations:
            return None, []

        haystack = f"{domain or ''} {text or ''}".lower()
        best: Optional[dict] = None
        reasons: list[str] = []

        for org in organizations:
            org_reasons: list[str] = []
            for asset in org.get("assets", []):
                value = str(asset["value"]).lower().strip()
                if not value:
                    continue
                if asset["asset_type"] in ("domain", "email_domain") and domain:
                    host = domain.lower()
                    if host == value or host.endswith("." + value):
                        org_reasons.append(f"Doğrulanmış domain eşleşmesi: {value}")
                elif value in haystack:
                    org_reasons.append(f"Metin içinde geçen varlık ({asset['asset_type']}): {value}")
            if org_reasons and (best is None or len(org_reasons) > len(reasons)):
                best, reasons = org, org_reasons

        return best, reasons

    def is_association_verified(self, organization_id: Optional[int], reasons: Sequence[str]) -> bool:
        return any("Doğrulanmış domain eşleşmesi" in r for r in reasons)

    # ------------------------------------------------------------------ #
    # Kaydetme
    # ------------------------------------------------------------------ #
    def save(
        self,
        finding: Finding,
        evidence: Optional[Evidence] = None,
        assess_risk: bool = True,
        association_verified: bool = False,
        actor: str = "system",
    ) -> FindingOutcome:
        """Bulguya kimlik/parmak izi atar, ilişkilendirir, değerlendirir ve kaydeder."""
        if not finding.finding_id:
            finding.finding_id = self.new_finding_id()
        if not finding.fingerprint:
            finding.fingerprint = finding_fingerprint(finding)

        existing = self.repos.findings.get_by_fingerprint(finding.fingerprint)
        if existing is not None:
            finding.finding_id = existing.finding_id
            finding.first_seen = existing.first_seen
            # Analist tarafından verilmiş durumu otomatik olarak geri alma.
            if existing.verification_status not in (
                VerificationStatus.NEW,
                VerificationStatus.UNVERIFIED_CLAIM,
            ):
                finding.verification_status = existing.verification_status
            finding.metadata = {**existing.metadata, **finding.metadata}

        if finding.organization_id is None and finding.finding_type != FindingType.IOC_MATCH:
            org, reasons = self.match_organization(
                domain=finding.matched_domain,
                text=f'{finding.organization or ""} {finding.evidence_summary}',
                explicit_name=finding.organization,
            )
            if org:
                finding.organization_id = org["id"]
                finding.organization = org["name"]
                finding.metadata["association_reasons"] = reasons
                association_verified = association_verified or self.is_association_verified(
                    org["id"], reasons
                )

        if assess_risk and self.risk_engine is not None:
            assessment = self.risk_engine.assess_finding(
                finding,
                evidence_count=len(self.repos.evidence.list_for_finding(finding.finding_id)) + (1 if evidence else 0),
                independent_sources=self._independent_source_count(finding),
                association_verified=association_verified,
            )
            finding.risk_level = assessment.level
            finding.risk_score = assessment.score
            finding.risk_reasons = assessment.reasons
            if assessment.verification_notes:
                finding.metadata["verification_notes"] = assessment.verification_notes

        saved, created, changed = self.repos.findings.upsert(finding)

        if evidence is not None:
            evidence.finding_id = saved.finding_id
            self.repos.evidence.add(evidence)

        if created:
            self.repos.audit.log(
                "finding_created",
                entity_type="finding",
                entity_id=saved.finding_id,
                detail={"finding_type": str(saved.finding_type), "source": saved.source_name},
                actor=actor,
            )
            self.notifier.on_new_finding(saved)
        elif changed:
            self.repos.audit.log(
                "finding_updated",
                entity_type="finding",
                entity_id=saved.finding_id,
                detail={"changed_fields": changed},
                actor=actor,
            )
            self.notifier.on_finding_changed(saved, changed)

        return FindingOutcome(finding=saved, created=created, changed_fields=changed)

    def _independent_source_count(self, finding: Finding) -> int:
        """Aynı iddiayı destekleyen bağımsız kaynak sayısı."""
        count = 1
        same = self.repos.findings.list(
            finding_type=finding.finding_type,
            organization_id=finding.organization_id,
            search=finding.matched_domain or None,
            limit=200,
        )
        sources = {
            f.source_name
            for f in same
            if (f.matched_domain or "") == (finding.matched_domain or "")
            and f.finding_id != finding.finding_id
        }
        sources.discard(finding.source_name)
        return count + len(sources)

    # ------------------------------------------------------------------ #
    # Durum yönetimi
    # ------------------------------------------------------------------ #
    def set_status(
        self,
        finding_id: str,
        status: VerificationStatus,
        note: Optional[str] = None,
        actor: str = "analyst",
        force: bool = False,
    ) -> Finding:
        """Doğrulama durumunu kurallı biçimde günceller.

        Satıcı ilanı veya forum gönderisi tek başına `Confirmed` olamaz: bu kural
        repository katmanında değil, çağrı bağlamında (analist kararı) uygulanır;
        ancak otomatik geçişler `can_transition` ile sınırlandırılır.
        """
        finding = self.repos.findings.get(finding_id)
        if finding is None:
            raise KeyError(f"Bulgu bulunamadı: {finding_id}")

        current = VerificationStatus(finding.verification_status)
        target = VerificationStatus(status)
        if not force and not can_transition(current, target):
            raise ValueError(f"Geçersiz durum geçişi: {current} → {target}")

        self.repos.findings.update_status(finding_id, target)
        if note:
            self.repos.notes.add(finding_id, note, author=actor)
        self.repos.audit.log(
            "finding_status_changed",
            entity_type="finding",
            entity_id=finding_id,
            detail={"from": str(current), "to": str(target), "forced": force},
            actor=actor,
        )
        updated = self.repos.findings.get(finding_id)
        assert updated is not None
        self.notifier.on_status_change(updated, current, target)
        return updated

    def add_note(self, finding_id: str, note: str, author: str = "analyst") -> AnalystNote:
        self.repos.notes.add(finding_id, note, author=author)
        self.repos.audit.log(
            "note_added", entity_type="finding", entity_id=finding_id, actor=author
        )
        notes = self.repos.notes.list_for_finding(finding_id)
        return notes[0]

    def reassess(self, finding_id: str, evidence_count: Optional[int] = None) -> Finding:
        """Mevcut kanıtlarla risk değerlendirmesini yeniler."""
        finding = self.repos.findings.get(finding_id)
        if finding is None:
            raise KeyError(f"Bulgu bulunamadı: {finding_id}")
        evidence_items = self.repos.evidence.list_for_finding(finding_id)
        assessment = self.risk_engine.assess_finding(
            finding,
            evidence_count=evidence_count if evidence_count is not None else len(evidence_items),
            independent_sources=self._independent_source_count(finding),
            association_verified=False,
        )
        self.repos.findings.update_risk(
            finding_id, assessment.level, assessment.score, assessment.reasons
        )
        refreshed = self.repos.findings.get(finding_id)
        assert refreshed is not None
        return refreshed

    # ------------------------------------------------------------------ #
    # Sorgulama
    # ------------------------------------------------------------------ #
    def get(self, finding_id: str) -> Optional[Finding]:
        return self.repos.findings.get(finding_id)

    def list(
        self,
        finding_type: Optional[FindingType] = None,
        verification_status: Optional[VerificationStatus] = None,
        risk_level: Optional[RiskLevel] = None,
        organization_id: Optional[int] = None,
        search: Optional[str] = None,
        limit: int = 200,
    ) -> list[Finding]:
        return self.repos.findings.list(
            finding_type=finding_type,
            verification_status=verification_status,
            risk_level=risk_level,
            organization_id=organization_id,
            search=search,
            limit=limit,
        )

    def details(self, finding_id: str) -> Optional[dict]:
        """Bulguyla birlikte kanıt ve notları döndürür."""
        finding = self.repos.findings.get(finding_id)
        if finding is None:
            return None
        return {
            "finding": finding,
            "evidence": self.repos.evidence.list_for_finding(finding_id),
            "notes": self.repos.notes.list_for_finding(finding_id),
        }

    def pending_review(self, limit: int = 50) -> list[Finding]:
        """Analist incelemesi bekleyen iddialar (Dashboard için)."""
        pending: list[Finding] = []
        for status in (
            VerificationStatus.NEW,
            VerificationStatus.UNDER_REVIEW,
            VerificationStatus.UNVERIFIED_CLAIM,
        ):
            pending.extend(self.list(verification_status=status, limit=limit))
        pending.sort(key=lambda f: f.last_checked, reverse=True)
        return pending[:limit]
