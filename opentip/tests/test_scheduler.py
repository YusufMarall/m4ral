"""Zamanlanmış kontrol ve kaynak izleme testleri (PRD 9.4, 9.5, 12).

Adaptörler sahte (mock) nesnelerdir; hiçbir gerçek ağ erişimi yapılmaz.
"""

from __future__ import annotations

import pytest

from core.finding_manager import FindingManager
from core.risk_engine import RiskEngine
from monitoring import MonitoringScheduler, NotificationService, SourceMonitor
from models import Finding, FindingType, RunStatus, SourceConfig, SourceType


def _raw_finding(reference: str, summary: str = "Sağlayıcı kaydı") -> Finding:
    """Sahte adaptörün `normalize_record` çıktısı olarak kullanılacak bulgu."""
    return Finding(
        finding_id="",
        finding_type=FindingType.BREACH_CLAIM,
        source_type=SourceType.BREACH_FEED,
        source_name="fake",
        source_reference=reference,
        evidence_summary=summary,
    )


def _build(repos, adapter) -> tuple[SourceMonitor, NotificationService]:
    notifier = NotificationService(repos)
    finder = FindingManager(repos, RiskEngine(), notifier)
    monitor = SourceMonitor(repos, [adapter], finder, notifier)
    return monitor, notifier


# --------------------------------------------------------------------------- #
# Kaynak çalıştırma
# --------------------------------------------------------------------------- #
def test_run_source_creates_finding_and_alert(
    repos, settings, register_source, make_adapter
) -> None:
    config = register_source("fake", check_interval_minutes=15)
    adapter = make_adapter(config, settings, raw_records=[_raw_finding("ref-1")])
    monitor, _ = _build(repos, adapter)

    result = monitor.run_source("fake")

    assert result.status == RunStatus.SUCCESS
    assert result.records_fetched == 1
    assert result.findings_created == 1
    assert result.changes.totals["new"] == 1
    assert len(repos.findings.list_by_source("fake")) == 1
    # Yeni kayıt alarm üretir (PRD 9.5, 12).
    assert any(alert.alert_type == "new_finding" for alert in repos.alerts.list())


def test_run_source_twice_does_not_create_duplicate_finding(
    repos, settings, register_source, make_adapter
) -> None:
    config = register_source("fake")
    adapter = make_adapter(config, settings, raw_records=[_raw_finding("ref-1")])
    monitor, _ = _build(repos, adapter)

    first = monitor.run_source("fake")
    second = monitor.run_source("fake")

    assert first.findings_created == 1
    assert second.findings_created == 0
    assert second.changes.totals["unchanged"] == 1
    assert len(repos.findings.list_by_source("fake")) == 1


def test_run_source_records_failure_without_losing_previous_state(
    repos, settings, register_source, make_adapter
) -> None:
    config = register_source("fake")
    healthy = make_adapter(config, settings, raw_records=[_raw_finding("ref-1")])
    monitor, _ = _build(repos, healthy)
    monitor.run_source("fake")

    failing = make_adapter(config, settings, error=RuntimeError("kaynak çöktü"))
    monitor.adapters["fake"] = failing

    result = monitor.run_source("fake")

    assert result.status == RunStatus.FAILED
    assert "kaynak çöktü" in (result.error or "")
    health = repos.sources.health("fake")
    assert health is not None
    assert health.consecutive_failures == 1
    # Başarılı kontrol zamanı korunur (PRD 9.4).
    assert health.last_success_at is not None
    run = repos.source_runs.last_run("fake")
    assert run is not None and run.status == RunStatus.FAILED


def test_run_source_requires_fetch_capability(
    repos, settings, register_source, make_adapter
) -> None:
    config = register_source("fake")
    adapter = make_adapter(config, settings)
    adapter.capabilities = {"connection_check"}
    monitor, _ = _build(repos, adapter)

    result = monitor.run_source("fake")

    assert result.status == RunStatus.FAILED
    assert "desteklemiyor" in (result.error or "")


# --------------------------------------------------------------------------- #
# Zamanlama yapılandırması
# --------------------------------------------------------------------------- #
def test_plan_jobs_includes_only_enabled_fetch_sources(
    repos, settings, register_source, make_adapter
) -> None:
    enabled_config = register_source("fake", check_interval_minutes=15)
    disabled_config = register_source("kapali", check_interval_minutes=30, enabled=False)
    enabled = make_adapter(enabled_config, settings)
    disabled = make_adapter(disabled_config, settings)
    monitor, _ = _build(repos, enabled)
    monitor.adapters[disabled.name] = disabled

    scheduler = MonitoringScheduler(monitor)
    jobs = scheduler.plan_jobs()

    assert jobs == [
        {"id": "source:fake", "source_name": "fake", "minutes": 15, "adapter": "fake"}
    ]
    # Zamanlayıcı başlatılmadan işler yalnızca plan olarak döner.
    assert scheduler.jobs()[0]["scheduled"] is False
    assert scheduler.is_running() is False


def test_plan_jobs_uses_minimum_one_minute(repos, settings, make_adapter) -> None:
    config = SourceConfig(
        name="fake",
        adapter="fake",
        source_type=SourceType.BREACH_FEED,
        check_interval_minutes=0,
    )
    monitor, _ = _build(repos, make_adapter(config, settings))

    jobs = MonitoringScheduler(monitor).plan_jobs()

    assert jobs[0]["minutes"] == 1


def test_run_now_triggers_manual_run(repos, settings, register_source, make_adapter) -> None:
    config = register_source("fake")
    adapter = make_adapter(config, settings, raw_records=[_raw_finding("ref-1")])
    monitor, _ = _build(repos, adapter)

    result = MonitoringScheduler(monitor).run_now("fake")

    assert result.status == RunStatus.SUCCESS
    run = repos.source_runs.last_run("fake")
    assert run is not None and run.triggered_by == "manual"


def test_run_source_raises_for_unknown_source(repos, settings, make_adapter) -> None:
    config = SourceConfig(name="fake", adapter="fake", source_type=SourceType.BREACH_FEED)
    monitor, _ = _build(repos, make_adapter(config, settings))

    with pytest.raises(KeyError):
        monitor.run_source("bilinmeyen")
