"""Analiz yöneticisi testleri (PRD 7.3, 8.5, 8.6, 19.3).

Kapsam:
- IOC'nin yalnızca uygun (etkin + `ioc_lookup` yetenekli) kaynaklara sorulması,
- Bir kaynağın çökmesinin diğer kaynakların sonucunu etkilememesi ve
  hatanın "eşleşme yok" olarak raporlanmaması,
- Kayıtların tekilleştirilmesi ve tekilleştirme sonrası kaynak şeffaflığı,
- Bulguların kalıcılığı ve bağımsız kaynak desteğine göre doğrulama durumu.
"""

from __future__ import annotations

import pytest

from core import IOCValidationError
from core.analyzer import AnalysisManager
from models import (
    IOCInput,
    IOCRecord,
    IOCType,
    RiskLevel,
    SourceConfig,
    SourceStatus,
    SourceType,
    VerificationStatus,
)


# --------------------------------------------------------------------------- #
# Sahte adaptörler
# --------------------------------------------------------------------------- #
class _StatusError(Exception):
    """`status` alanı taşıyan adaptör hatası (ör. `AdapterUnavailable`)."""

    def __init__(self, message: str, status: SourceStatus = SourceStatus.ERROR) -> None:
        super().__init__(message)
        self.status = status


class FakeIOCAdapter:
    """`IOCAdapter` protokolünü karşılayan asgari sahte adaptör."""

    def __init__(
        self,
        name: str = "otx",
        *,
        records: list[IOCRecord] | None = None,
        error: Exception | None = None,
        enabled: bool = True,
        capabilities: set[str] | None = None,
        reliability: float = 0.6,
    ) -> None:
        self.name = name
        self.enabled = enabled
        self.source_type = SourceType.IOC_FEED
        self.capabilities = (
            {"ioc_lookup", "connection_check"} if capabilities is None else set(capabilities)
        )
        self.records = list(records or [])
        self.error = error
        self.queries: list[IOCInput] = []
        self.source_config = SourceConfig(
            name=name, adapter=name, source_type=SourceType.IOC_FEED, reliability=reliability
        )

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities

    def lookup_ioc(self, ioc: IOCInput) -> list[IOCRecord]:
        self.queries.append(ioc)
        if self.error is not None:
            raise self.error
        return list(self.records)

    def check_connection(self) -> bool:
        return self.error is None


class ReadyAwareFakeIOCAdapter(FakeIOCAdapter):
    def __init__(self, *args, ready: bool = True, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._ready = ready

    def is_ready(self) -> bool:
        return self._ready


def _record(
    value: str = "evil.example",
    *,
    source: str = "otx",
    risk: RiskLevel = RiskLevel.HIGH,
    tags: list[str] | None = None,
) -> IOCRecord:
    return IOCRecord(
        value=value,
        ioc_type=IOCType.DOMAIN,
        source_name=source,
        source_type=SourceType.IOC_FEED,
        risk_level=risk,
        confidence=0.8,
        tags=list(tags or ["apt"]),
    )


def _manager(repos, *adapters) -> AnalysisManager:
    return AnalysisManager(repos, list(adapters))


# --------------------------------------------------------------------------- #
# Kaynak seçimi
# --------------------------------------------------------------------------- #
def test_analyze_ioc_without_enabled_source_adds_note_and_no_records(repos) -> None:
    adapter = FakeIOCAdapter("otx", enabled=False)

    result = _manager(repos, adapter).analyze_ioc("evil.example")

    assert result.source_results == []
    assert result.deduplicated_records == []
    assert result.finished_at is not None
    assert any("etkin bir IOC kaynağı bulunamadı" in note for note in result.notes)
    assert adapter.queries == []


def test_ioc_adapters_filters_disabled_and_unsupported() -> None:
    supported = FakeIOCAdapter("otx")
    disabled = FakeIOCAdapter("misp", enabled=False)
    no_lookup = FakeIOCAdapter("breach", capabilities={"connection_check"})

    manager = AnalysisManager.__new__(AnalysisManager)
    manager.adapters = [supported, disabled, no_lookup]

    assert manager.ioc_adapters() == [supported]
    assert manager.ioc_adapters(["misp"]) == []


def test_ioc_adapters_skips_enabled_but_not_ready_sources() -> None:
    ready = ReadyAwareFakeIOCAdapter("otx", ready=True)
    not_ready = ReadyAwareFakeIOCAdapter("misp", ready=False)

    manager = AnalysisManager.__new__(AnalysisManager)
    manager.adapters = [ready, not_ready]

    assert manager.ioc_adapters() == [ready]


def test_adapter_names_filter_restricts_queried_sources(repos) -> None:
    otx = FakeIOCAdapter("otx", records=[_record(source="otx")])
    threatfox = FakeIOCAdapter("threatfox", records=[_record(source="threatfox")])

    result = _manager(repos, otx, threatfox).analyze_ioc(
        "evil.example", adapter_names=["otx"], persist=False
    )

    assert otx.queries and not threatfox.queries
    assert [r.source_name for r in result.source_results] == ["otx"]


def test_analyze_ioc_normalizes_value_before_querying(repos) -> None:
    adapter = FakeIOCAdapter("otx")

    _manager(repos, adapter).analyze_ioc("  EVIL.Example.  ", persist=False)

    assert adapter.queries[0].value == "evil.example"
    assert adapter.queries[0].ioc_type == IOCType.DOMAIN


def test_analyze_ioc_rejects_unsupported_value(repos) -> None:
    with pytest.raises(IOCValidationError):
        _manager(repos, FakeIOCAdapter("otx")).analyze_ioc("bu bir ioc değil")


# --------------------------------------------------------------------------- #
# Hata izolasyonu
# --------------------------------------------------------------------------- #
def test_source_failure_is_isolated_and_not_reported_as_clean(repos) -> None:
    ok = FakeIOCAdapter("otx", records=[_record(source="otx")])
    broken = FakeIOCAdapter("misp", error=_StatusError("zaman aşımı"))

    result = _manager(repos, ok, broken).analyze_ioc("evil.example")

    states = {r.source_name: r.status for r in result.source_results}
    assert states == {"otx": SourceStatus.OK, "misp": SourceStatus.ERROR}
    assert result.failed_sources == ["misp"]
    assert len(result.deduplicated_records) == 1

    failed = next(r for r in result.source_results if r.source_name == "misp")
    assert failed.error == "_StatusError: zaman aşımı"
    assert failed.has_error is True
    assert failed.matched is False


def test_adapter_error_status_comes_from_exception(repos) -> None:
    broken = FakeIOCAdapter(
        "misp", error=_StatusError("servis kapalı", status=SourceStatus.UNAVAILABLE)
    )

    result = _manager(repos, broken).analyze_ioc("evil.example")

    assert result.source_results[0].status == SourceStatus.UNAVAILABLE
    assert result.failed_sources == ["misp"]


def test_duration_is_recorded_for_every_source(repos) -> None:
    result = _manager(repos, FakeIOCAdapter("otx")).analyze_ioc("evil.example", persist=False)

    assert result.source_results[0].duration_ms is not None
    assert result.source_results[0].duration_ms >= 0


# --------------------------------------------------------------------------- #
# Tekilleştirme ve risk
# --------------------------------------------------------------------------- #
def test_records_from_multiple_sources_are_merged_with_source_transparency(repos) -> None:
    otx = FakeIOCAdapter("otx", records=[_record(source="otx", tags=["apt"])])
    threatfox = FakeIOCAdapter(
        "threatfox", records=[_record(source="threatfox", tags=["c2"], risk=RiskLevel.CRITICAL)]
    )

    result = _manager(repos, otx, threatfox).analyze_ioc("evil.example", persist=False)

    assert len(result.deduplicated_records) == 1
    merged = result.deduplicated_records[0]
    names = [entry["source_name"] for entry in merged.detail["sources"]]
    assert names == ["otx", "threatfox"]
    assert merged.tags == ["apt", "c2"]
    assert merged.risk_level == RiskLevel.CRITICAL


def test_risk_is_assessed_for_the_whole_analysis(repos) -> None:
    adapter = FakeIOCAdapter("otx", records=[_record(risk=RiskLevel.HIGH)])

    result = _manager(repos, adapter).analyze_ioc("evil.example", persist=False)

    assert result.risk_level != RiskLevel.UNASSESSED
    assert result.risk_score is not None
    assert result.risk_reasons


# --------------------------------------------------------------------------- #
# Kalıcılık
# --------------------------------------------------------------------------- #
def test_persist_writes_ioc_records_and_findings(repos) -> None:
    _manager(repos, FakeIOCAdapter("otx", records=[_record()])).analyze_ioc("evil.example")

    assert repos.iocs.count() >= 1
    findings = repos.findings.list()
    assert len(findings) == 1
    assert findings[0].ioc_value == "evil.example"
    assert findings[0].matched_domain == "evil.example"
    assert findings[0].risk_score is not None


def test_persist_marks_single_source_match_as_unverified_claim(repos) -> None:
    _manager(repos, FakeIOCAdapter("otx", records=[_record()])).analyze_ioc("evil.example")

    assert repos.findings.list()[0].verification_status == VerificationStatus.UNVERIFIED_CLAIM


def test_persist_marks_corroborated_when_two_sources_report_same_indicator(repos) -> None:
    """Aynı göstergeyi iki bağımsız kaynak bildirdiyse bulgu 'corroborated' olur (PRD 8.5)."""
    otx = FakeIOCAdapter("otx", records=[_record(source="otx")])
    threatfox = FakeIOCAdapter("threatfox", records=[_record(source="threatfox")])

    _manager(repos, otx, threatfox).analyze_ioc("evil.example")

    statuses = {f.verification_status for f in repos.findings.list()}
    assert statuses == {VerificationStatus.CORROBORATED}


def test_different_indicators_from_two_sources_are_not_corroborated(repos) -> None:
    """Farklı göstergeler tek başına doğrulama desteği sayılmaz."""
    otx = FakeIOCAdapter("otx", records=[_record("a.example", source="otx")])
    threatfox = FakeIOCAdapter("threatfox", records=[_record("b.example", source="threatfox")])

    _manager(repos, otx, threatfox).analyze_ioc("a.example")

    statuses = {f.verification_status for f in repos.findings.list()}
    assert VerificationStatus.CORROBORATED not in statuses


def test_persist_false_leaves_database_untouched(repos) -> None:
    _manager(repos, FakeIOCAdapter("otx", records=[_record()])).analyze_ioc(
        "evil.example", persist=False
    )

    assert repos.iocs.count() == 0
    assert repos.findings.count() == 0


def test_failed_source_writes_no_findings(repos) -> None:
    broken = FakeIOCAdapter("misp", error=_StatusError("bağlantı kurulamadı"))

    _manager(repos, broken).analyze_ioc("evil.example")

    assert repos.findings.count() == 0
    assert repos.iocs.count() == 0


def test_second_analysis_does_not_duplicate_findings(repos) -> None:
    adapter = FakeIOCAdapter("otx", records=[_record()])
    manager = _manager(repos, adapter)

    manager.analyze_ioc("evil.example")
    manager.analyze_ioc("evil.example")

    assert repos.findings.count() == 1
