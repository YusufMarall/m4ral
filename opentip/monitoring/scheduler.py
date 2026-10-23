"""Zamanlanmış kontrol sistemi (PRD 9.4).

`SourceMonitor` bir kaynağın kontrol çalışmasını uçtan uca yürütür:
adaptör çalışır → kayıtlar normalize edilir → önceki kayıtlarla karşılaştırılır
→ yeni/güncellenen bulgular kaydedilir → hatalar ve kontrol zamanı saklanır
→ gerekirse alarm üretilir.

`MonitoringScheduler` bu çalışmayı kaynak bazında periyodik hale getirir.
Sağlayıcının rate limit ve kullanım koşulları her zaman önceliklidir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from models import (
    ChangeType,
    Evidence,
    Finding,
    FindingType,
    RunStatus,
    SourceStatus,
    SourceType,
    utcnow,
)
from core.deduplicator import finding_fingerprint
from core.finding_manager import FindingManager
from storage import Repositories

from .change_detector import ChangeSummary, ChangeDetector
from .notifications import NotificationService


@dataclass
class SourceUpdateResult:
    """Bir kaynak kontrolünün sonucu."""

    source_name: str
    status: RunStatus
    run_id: Optional[int] = None
    records_fetched: int = 0
    findings_created: int = 0
    findings_updated: int = 0
    normalize_errors: int = 0
    error: Optional[str] = None
    changes: ChangeSummary = field(default_factory=ChangeSummary)

    @property
    def summary_text(self) -> str:
        totals = self.changes.totals
        return (
            f"{self.source_name}: {self.records_fetched} kayıt alındı, "
            f"{self.findings_created} yeni bulgu, {self.findings_updated} güncelleme "
            f"(yeni: {totals['new']}, değişen: {totals['updated']}, "
            f"değişmeyen: {totals['unchanged']}, kayıp: {totals['missing']})"
        )


class SourceMonitor:
    """Yapılandırılmış kaynakların kontrolünü yürütür."""

    def __init__(
        self,
        repos: Repositories,
        adapters: Sequence[Any],
        finding_manager: FindingManager,
        notifier: NotificationService,
        change_detector: Optional[ChangeDetector] = None,
    ) -> None:
        self.repos = repos
        self.adapters: dict[str, Any] = {a.name: a for a in adapters}
        self.finding_manager = finding_manager
        self.notifier = notifier
        self.change_detector = change_detector or ChangeDetector(repos)

    # ------------------------------------------------------------------ #
    def enabled_adapters(self) -> list[Any]:
        return [a for a in self.adapters.values() if a.enabled]

    def run_all(self) -> list[SourceUpdateResult]:
        return [self.run_source(name) for name in list(self.adapters.keys())]

    def run_source(self, source_name: str, triggered_by: str = "manual") -> SourceUpdateResult:
        """Tek bir kaynağı kontrol eder."""
        adapter = self.adapters.get(source_name)
        if adapter is None:
            raise KeyError(f"Adaptör bulunamadı: {source_name}")

        if not adapter.supports("fetch_updates"):
            error = f"{source_name} adaptörü periyodik kayıt çekmeyi desteklemiyor."
            return SourceUpdateResult(source_name=source_name, status=RunStatus.FAILED, error=error)

        health_before = self.repos.sources.health(source_name)
        was_failing = bool(health_before and health_before.consecutive_failures >= 1)
        since = (
            health_before.last_success_at.isoformat()
            if health_before and health_before.last_success_at
            else None
        )

        run_id = self.repos.source_runs.start(
            source_name=source_name,
            source_id=adapter.source_config.source_id,
            triggered_by=triggered_by,
        )

        # 1) Kaynaktan veri çekme
        try:
            raw_records = adapter.fetch_updates(since=since) or []
        except Exception as exc:
            status = getattr(exc, "status", SourceStatus.ERROR)
            message = f"{type(exc).__name__}: {exc}"
            self.repos.sources.record_run_result(source_name, status, message, success=False)
            self.repos.source_runs.finish(run_id, RunStatus.FAILED, error_message=message)
            self.repos.audit.log(
                "source_run_failed",
                entity_type="source",
                entity_id=source_name,
                detail={"error": message, "triggered_by": triggered_by},
            )
            # Kaynak hatası nedeniyle kontrol edilemeyen kayıtlar ayrı işaretlenir.
            self.notifier.notify_source_status(source_name, status, message, was_failing=was_failing)
            changes, _ = self.change_detector.classify(
                source_name, [], source_ok=False, finding_type=self._default_finding_type(adapter)
            )
            return SourceUpdateResult(
                source_name=source_name,
                status=RunStatus.FAILED,
                run_id=run_id,
                error=message,
                changes=changes,
            )

        # 2) Normalizasyon
        findings, normalize_errors = self._normalize(adapter, raw_records)

        # 3) Değişiklik tespiti
        source_ok = normalize_errors < max(1, len(raw_records))
        changes, to_save = self.change_detector.classify(
            source_name, findings, source_ok=source_ok, finding_type=self._default_finding_type(adapter)
        )

        # 4) Yeni/güncellenen bulguları kaydet
        created = updated = 0
        for finding in to_save:
            evidence = Evidence(
                source_name=finding.source_name,
                source_type=finding.source_type,
                source_reference=finding.source_reference,
                collected_at=utcnow(),
                summary=finding.evidence_summary,
                content_type="application/json",
                content_digest=finding.metadata.get("content_digest"),
                confidence=finding.source_reliability,
            )
            outcome = self.finding_manager.save(
                finding, evidence=evidence, actor=f"source:{source_name}"
            )
            if outcome.created:
                created += 1
            elif outcome.changed:
                updated += 1

        # 5) Durum ve sayaçları kaydet
        if not source_ok:
            status = RunStatus.PARTIAL
            message = f"{normalize_errors}/{len(raw_records)} kayıt işlenemedi"
        else:
            status = RunStatus.SUCCESS
            message = f"{len(raw_records)} kayıt"

        self.repos.source_runs.finish(
            run_id,
            status,
            records_fetched=len(raw_records),
            findings_created=created,
            findings_updated=updated,
            error_message=message if status == RunStatus.PARTIAL else None,
        )
        self.repos.sources.record_run_result(source_name, SourceStatus.OK, message, success=True)
        self.notifier.notify_source_status(
            source_name, SourceStatus.OK, message, was_failing=was_failing
        )
        self.repos.audit.log(
            "source_run_completed",
            entity_type="source",
            entity_id=source_name,
            detail={
                "records": len(raw_records),
                "created": created,
                "updated": updated,
                "changes": changes.totals,
                "triggered_by": triggered_by,
            },
        )

        return SourceUpdateResult(
            source_name=source_name,
            status=status,
            run_id=run_id,
            records_fetched=len(raw_records),
            findings_created=created,
            findings_updated=updated,
            normalize_errors=normalize_errors,
            changes=changes,
        )

    # ------------------------------------------------------------------ #
    def _normalize(self, adapter: Any, raw_records: Sequence[Any]) -> tuple[list[Finding], int]:
        """Ham kayıtları ortak modele dönüştürür; hatalı kayıtları sayar."""
        findings: list[Finding] = []
        errors = 0
        for raw in raw_records:
            try:
                finding = adapter.normalize_record(raw)
            except Exception as exc:
                errors += 1
                adapter.logger.warning("Kayıt normalize edilemedi: %s", exc)
                continue
            if finding is None:
                continue
            if not finding.fingerprint:
                finding.fingerprint = finding_fingerprint(finding)
            findings.append(finding)
        return findings, errors

    @staticmethod
    def _default_finding_type(adapter: Any) -> FindingType:
        """Adaptörün ürettiği varsayılan bulgu türü (değişiklik karşılaştırması için)."""
        if getattr(adapter, "source_type", None) == SourceType.DARKWEB_SOURCE:
            return FindingType.DARKWEB_RECORD
        return FindingType.BREACH_CLAIM

    def close(self) -> None:
        for adapter in self.adapters.values():
            adapter.close()


class MonitoringScheduler:
    """Kaynak kontrollerini periyodik olarak çalıştırır."""

    def __init__(self, monitor: SourceMonitor, timezone: str = "UTC") -> None:
        self.monitor = monitor
        self.timezone = timezone
        self._scheduler: Any = None

    # ------------------------------------------------------------------ #
    def plan_jobs(self) -> list[dict[str, Any]]:
        """Etkin kaynaklar için zamanlanacak işleri hesaplar (APScheduler gerektirmez)."""
        jobs: list[dict[str, Any]] = []
        for adapter in self.monitor.enabled_adapters():
            if not adapter.supports("fetch_updates"):
                continue
            interval = max(1, int(adapter.source_config.check_interval_minutes))
            jobs.append(
                {
                    "id": f"source:{adapter.name}",
                    "source_name": adapter.name,
                    "minutes": interval,
                    "adapter": adapter.adapter_name,
                }
            )
        return jobs

    def start(self) -> None:
        """Zamanlayıcıyı başlatır. Etkin kaynak yoksa boş çalışır."""
        from apscheduler.schedulers.background import BackgroundScheduler

        if self._scheduler is not None:
            return
        self._scheduler = BackgroundScheduler(timezone=self.timezone)
        for job in self.plan_jobs():
            self.add_job(job["source_name"], job["minutes"])
        self._scheduler.start()

    def add_job(self, source_name: str, minutes: int) -> None:
        if self._scheduler is None:
            return
        self._scheduler.add_job(
            self._run_job,
            "interval",
            minutes=max(1, int(minutes)),
            id=f"source:{source_name}",
            name=f"Kaynak kontrolü: {source_name}",
            args=[source_name],
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )

    def remove_job(self, source_name: str) -> None:
        if self._scheduler is None:
            return
        try:
            self._scheduler.remove_job(f"source:{source_name}")
        except Exception:  # iş yoksa yok sayılır
            pass

    def _run_job(self, source_name: str) -> None:
        """Zamanlayıcı işi: hatalar zamanlayıcıyı durdurmamalıdır."""
        try:
            self.monitor.run_source(source_name, triggered_by="scheduler")
        except Exception:  # pragma: no cover - hata kayıt altına alınır
            self.monitor.repos.audit.log(
                "scheduled_run_error", entity_type="source", entity_id=source_name
            )

    def run_now(self, source_name: str) -> SourceUpdateResult:
        return self.monitor.run_source(source_name, triggered_by="manual")

    def is_running(self) -> bool:
        return bool(self._scheduler and self._scheduler.running)

    def jobs(self) -> list[dict[str, Any]]:
        if self._scheduler is None:
            return [
                {**job, "next_run_time": None, "scheduled": False} for job in self.plan_jobs()
            ]
        return [
            {
                "id": job.id,
                "source_name": job.args[0] if job.args else job.id,
                "minutes": int(job.trigger.interval.total_seconds() // 60),
                "next_run_time": job.next_run_time,
                "scheduled": True,
            }
            for job in self._scheduler.get_jobs()
        ]

    def shutdown(self, wait: bool = False) -> None:
        if self._scheduler is not None:
            self._scheduler.shutdown(wait=wait)
            self._scheduler = None
