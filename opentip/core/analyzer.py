"""Analiz yöneticisi (PRD 7.3, 8.6).

Bir IOC veya sızıntı kaydını tüm uygun kaynaklara sorgular, yanıtları ortak
modele dönüştürür, tekilleştirir, risk değerlendirmesi yapar ve kaydeder.

Kritik kural: bir kaynağın yanıt vermemesi "gösterge temiz" olarak
yorumlanmaz; kaynak hatası ayrı bir durum olarak raporlanır (PRD 7.3, 19.3).
"""

from __future__ import annotations

from time import perf_counter
from typing import Any, Optional, Protocol, Sequence, runtime_checkable

from models import (
    AnalysisResult,
    Finding,
    FindingType,
    IOCInput,
    IOCRecord,
    IOCSourceResult,
    IOCType,
    SourceStatus,
    SourceType,
    VerificationStatus,
    utcnow,
)
from storage import Repositories
from .deduplicator import deduplicate_records, ioc_fingerprint
from .finding_manager import FindingManager, NullNotifier
from .ioc_validator import validate_ioc
from .risk_engine import RiskEngine


@runtime_checkable
class IOCAdapter(Protocol):
    """`AnalysisManager`'ın beklediği adaptör arayüzü (yapısal tiplendirme).

    Bu protokol sayesinde `core` katmanı `adapters` paketine bağımlı olmaz.
    """

    name: str
    enabled: bool
    source_type: SourceType
    capabilities: set[str]

    def supports(self, capability: str) -> bool: ...

    def lookup_ioc(self, ioc: IOCInput) -> list[IOCRecord]: ...

    def check_connection(self) -> bool: ...


class AnalysisManager:
    """IOC analiz akışını yönetir."""

    def __init__(
        self,
        repos: Repositories,
        adapters: Sequence[Any] = (),
        risk_engine: Optional[RiskEngine] = None,
        finding_manager: Optional[FindingManager] = None,
    ) -> None:
        self.repos = repos
        self.adapters: list[Any] = list(adapters)
        self.risk_engine = risk_engine or RiskEngine()
        self.finding_manager = finding_manager or FindingManager(
            repos, self.risk_engine, NullNotifier()
        )

    def set_adapters(self, adapters: Sequence[Any]) -> None:
        self.adapters = list(adapters)

    # ------------------------------------------------------------------ #
    def ioc_adapters(self, only_names: Optional[Sequence[str]] = None) -> list[Any]:
        selected = []
        for adapter in self.adapters:
            if not getattr(adapter, "enabled", False):
                continue
            is_ready = getattr(adapter, "is_ready", None)
            if callable(is_ready) and not is_ready():
                continue
            if not adapter.supports("ioc_lookup"):
                continue
            if only_names and adapter.name not in set(only_names):
                continue
            selected.append(adapter)
        return selected

    def analyze_ioc(
        self,
        value: str,
        declared_type: Optional[IOCType] = None,
        adapter_names: Optional[Sequence[str]] = None,
        persist: bool = True,
    ) -> AnalysisResult:
        """Tek bir IOC'yi tüm uygun kaynaklarda analiz eder."""
        parsed: IOCInput = validate_ioc(value, declared_type)
        result = AnalysisResult(value=parsed.value, ioc_type=parsed.ioc_type)  # type: ignore[arg-type]

        adapters = self.ioc_adapters(adapter_names)
        if not adapters:
            result.notes.append(
                "Yapılandırılmış ve etkin bir IOC kaynağı bulunamadı. "
                ".env dosyasından kaynak anahtarlarını ve etkinlik durumunu kontrol edin."
            )
            result.finished_at = utcnow()
            return result

        all_records: list[IOCRecord] = []
        for adapter in adapters:
            source_result = self._query_adapter(adapter, parsed)
            result.source_results.append(source_result)
            all_records.extend(source_result.records)

        deduplicated = deduplicate_records(all_records)
        result.deduplicated_records = deduplicated

        reliability = self._average_reliability(adapters)
        assessment = self.risk_engine.assess_ioc(
            parsed.ioc_type, deduplicated, result.source_results, source_reliability=reliability
        )
        result.risk_level = assessment.level
        result.risk_score = assessment.score
        result.risk_reasons = assessment.reasons
        result.notes.extend(assessment.verification_notes)

        if persist:
            self._persist(parsed, result)

        result.finished_at = utcnow()
        return result

    # ------------------------------------------------------------------ #
    def _query_adapter(self, adapter: Any, ioc: IOCInput) -> IOCSourceResult:
        """Tek bir adaptörü güvenli biçimde sorgular.

        Adaptör hataları diğer kaynakların sonucunu etkilemez ve asla
        "eşleşme yok" olarak raporlanmaz.
        """
        started = perf_counter()
        source_result = IOCSourceResult(
            source_name=adapter.name,
            source_type=getattr(adapter, "source_type", SourceType.IOC_FEED),
        )
        try:
            records = adapter.lookup_ioc(ioc) or []
            source_result.records = records
            source_result.status = SourceStatus.OK
        except Exception as exc:  # adaptör hatası izole edilir
            status = getattr(exc, "status", SourceStatus.ERROR)
            source_result.status = status
            source_result.error = f"{type(exc).__name__}: {exc}"
        source_result.duration_ms = int((perf_counter() - started) * 1000)
        source_result.checked_at = utcnow()
        return source_result

    @staticmethod
    def _average_reliability(adapters: Sequence[Any]) -> float:
        values = [
            float(getattr(getattr(a, "source_config", None), "reliability", 0.5)) for a in adapters
        ]
        return round(sum(values) / len(values), 3) if values else 0.5

    @staticmethod
    def _supporting_sources(records: Sequence[IOCRecord]) -> dict[tuple[str, str], set[str]]:
        """Gösterge başına onu bildiren bağımsız kaynak adlarını toplar.

        Tekilleştirilmiş kaydın `detail["sources"]` listesi tüm kaynakları
        taşır; bu sayede aynı göstergenin kaç kaynak tarafından bildirildiği
        doğru hesaplanır (PRD 8.5, 9.5).
        """
        support: dict[tuple[str, str], set[str]] = {}
        for record in records:
            key = (str(record.ioc_type), record.value)
            names = support.setdefault(key, set())
            names.add(record.source_name)
            for entry in record.detail.get("sources") or []:
                if isinstance(entry, dict) and entry.get("source_name"):
                    names.add(str(entry["source_name"]))
        return support

    def _persist(self, ioc: IOCInput, result: AnalysisResult) -> None:
        """IOC kayıtlarını ve bulguları veritabanına yazar."""
        for record in result.deduplicated_records:
            if not record.fingerprint:
                record.fingerprint = ioc_fingerprint(record)
            self.repos.iocs.upsert(record)

        for source_result in result.source_results:
            if source_result.has_error:
                continue
            # Tekilleştirme öncesi kaynak bazlı kayıtlar da saklanır (kaynak şeffaflığı).
            for record in source_result.records:
                if not record.fingerprint:
                    record.fingerprint = ioc_fingerprint(record)
                self.repos.iocs.upsert(record)

                finding = self._build_ioc_finding(ioc, record, result)
                self.finding_manager.save(finding, assess_risk=False, actor="analyzer")

    def _build_ioc_finding(
        self, ioc: IOCInput, record: IOCRecord, result: AnalysisResult
    ) -> Finding:
        matched_domain = ioc.value if ioc.ioc_type in (IOCType.DOMAIN, IOCType.URL) else None
        if ioc.ioc_type == IOCType.URL:
            matched_domain = ioc.value.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]

        # Tek kaynaklı eşleşme doğrulanmış sayılmaz; aynı göstergeyi bildiren
        # bağımsız kaynak sayısı birden fazlaysa "Corroborated" olarak işaretlenir
        # (PRD 8.5). Tekilleştirme kaydı tek bir kayda indirdiği için destek
        # sayısı `record.source_name` üzerinden değil, birleştirilmiş kaydın
        # kaynak listesinden okunur.
        key = (str(record.ioc_type), record.value)
        supporting_sources = self._supporting_sources(result.deduplicated_records)
        verification_status = (
            VerificationStatus.CORROBORATED
            if len(supporting_sources.get(key, {record.source_name})) > 1
            else VerificationStatus.UNVERIFIED_CLAIM
        )

        finding = Finding(
            finding_id="",
            finding_type=FindingType.IOC_MATCH,
            matched_domain=matched_domain,
            ioc_value=record.value,
            ioc_type=record.ioc_type,
            source_type=record.source_type,
            source_name=record.source_name,
            source_reference=record.source_reference,
            first_seen=record.first_seen,
            last_checked=result.finished_at or utcnow(),
            verification_status=verification_status,
            risk_level=result.risk_level,
            risk_score=result.risk_score,
            risk_reasons=result.risk_reasons,
            evidence_summary=(
                f"{record.source_name} kaynağı bu göstergeyi bildirdi. "
                f"Etiketler: {', '.join(record.tags) or 'yok'}."
            ),
            source_reliability=record.confidence,
            metadata={"tags": record.tags, "detail": record.detail, "ioc_type": str(record.ioc_type)},
        )
        return finding
