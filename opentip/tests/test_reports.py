"""Rapor dışa aktarma testleri (PRD 13, 19.12, 19.13).

Kapsam:
- JSON ve HTML raporlarının üretilmesi ve beklenen alanları içermesi,
- Hassas anahtarların (API anahtarı, token vb.) rapora sızmaması,
- Doğrulama durumu ile risk seviyesinin raporda ayrı gösterilmesi,
- Raporların çıktı dizinine yazılması ve denetim kaydına işlenmesi.
"""

from __future__ import annotations

import json

from core.deduplicator import finding_fingerprint
from models import (
    AnalysisResult,
    Finding,
    FindingType,
    IOCRecord,
    IOCSourceResult,
    IOCType,
    RiskLevel,
    SourceStatus,
    SourceType,
    VerificationStatus,
    utcnow,
)
from reports import ReportExporter, scrub


# --------------------------------------------------------------------------- #
# Yardımcılar
# --------------------------------------------------------------------------- #
def _finding(
    *,
    finding_id: str = "",
    reference: str = "forum-post-123",
    source: str = "breach_feed",
    organization: str | None = "Nesil Teknoloji",
    domain: str | None = "example.com",
    risk: RiskLevel = RiskLevel.HIGH,
    verification: VerificationStatus = VerificationStatus.UNVERIFIED_CLAIM,
    summary: str = "Doğrulanmamış ifşa iddiası",
    metadata: dict | None = None,
) -> Finding:
    finding = Finding(
        finding_id=finding_id,
        finding_type=FindingType.BREACH_CLAIM,
        organization=organization,
        matched_domain=domain,
        source_type=SourceType.BREACH_FEED,
        source_name=source,
        source_reference=reference,
        risk_level=risk,
        verification_status=verification,
        evidence_summary=summary,
        metadata=dict(metadata or {}),
    )
    finding.fingerprint = finding_fingerprint(finding)
    return finding


def _store(repos, finding: Finding) -> Finding:
    finding.finding_id = finding.finding_id or f"F-{finding.source_reference}"
    saved, created, _ = repos.findings.upsert(finding)
    assert created is True
    return saved


def _record(
    value: str = "evil.example",
    *,
    source: str = "otx",
    risk: RiskLevel = RiskLevel.HIGH,
    tags: list[str] | None = None,
    corroborating: list[str] | None = None,
) -> IOCRecord:
    names = corroborating or [source]
    return IOCRecord(
        value=value,
        ioc_type=IOCType.DOMAIN,
        source_name=source,
        source_type=SourceType.IOC_FEED,
        risk_level=risk,
        confidence=0.8,
        tags=list(tags or ["apt", "phishing"]),
        detail={"sources": [{"source_name": name} for name in names]},
    )


def _analysis(records: list[IOCRecord], *, failed: list[str] | None = None) -> AnalysisResult:
    source_results = [
        IOCSourceResult(
            source_name="otx",
            source_type=SourceType.IOC_FEED,
            status=SourceStatus.OK,
            records=list(records),
            duration_ms=120,
        )
    ]
    for name in failed or []:
        source_results.append(
            IOCSourceResult(
                source_name=name,
                source_type=SourceType.IOC_FEED,
                status=SourceStatus.ERROR,
                error="zaman aşımı",
            )
        )
    return AnalysisResult(
        value=records[0].value if records else "evil.example",
        ioc_type=IOCType.DOMAIN,
        finished_at=utcnow(),
        source_results=source_results,
        deduplicated_records=list(records),
        risk_level=RiskLevel.HIGH,
        risk_score=74.0,
        risk_reasons=["Tek kaynakta görülme"],
        notes=["Kaynak yanıtı 120 ms sürdü"],
    )


# --------------------------------------------------------------------------- #
# Bulgu raporları
# --------------------------------------------------------------------------- #
def test_export_findings_json_writes_public_findings_with_stats(repos, settings) -> None:
    _store(repos, _finding())
    exporter = ReportExporter(repos, settings.report_dir)

    path = exporter.export_findings_json(repos.findings.list())
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert path.suffix == ".json"
    assert payload["finding_count"] == 1
    assert payload["stats"]["total"] == 1
    assert payload["stats"]["by_risk"] == {"high": 1}
    item = payload["findings"][0]
    assert item["target"] == "Nesil Teknoloji"
    assert item["verification_status"] == "unverified_claim"
    assert item["risk_level"] == "high"


def test_export_findings_json_omits_internal_metadata(repos, settings) -> None:
    """Genel rapor yalnızca beyaz listedeki alanları yazar; ham metadata yazılmaz."""
    _store(repos, _finding(metadata={"api_key": "SUPERSECRET-VALUE", "raw": "ham yanıt"}))
    exporter = ReportExporter(repos, settings.report_dir)

    blob = exporter.export_findings_json(repos.findings.list()).read_text(encoding="utf-8")

    assert "SUPERSECRET-VALUE" not in blob
    assert "metadata" not in blob


def test_export_findings_json_accepts_custom_filename(repos, settings) -> None:
    _store(repos, _finding())
    exporter = ReportExporter(repos, settings.report_dir)

    path = exporter.export_findings_json(repos.findings.list(), filename="ozel.json")

    assert path.name == "ozel.json"
    assert path.parent == settings.report_dir


def test_export_findings_json_without_findings_is_empty(repos, settings) -> None:
    exporter = ReportExporter(repos, settings.report_dir)

    payload = json.loads(
        exporter.export_findings_json([]).read_text(encoding="utf-8")
    )

    assert payload["finding_count"] == 0
    assert payload["findings"] == []
    assert payload["stats"]["total"] == 0


def test_export_findings_html_keeps_verification_and_risk_separate(repos, settings) -> None:
    """Doğrulanmamış bir iddia yüksek riskli olabilir; ikisi ayrı gösterilir (PRD 1, 13)."""
    _store(repos, _finding(risk=RiskLevel.HIGH, verification=VerificationStatus.UNVERIFIED_CLAIM))
    exporter = ReportExporter(repos, settings.report_dir)

    html = exporter.export_findings_html(repos.findings.list()).read_text(encoding="utf-8")

    assert "OpenTIP Bulgu Raporu" in html
    assert "F-forum-post-123" in html
    assert "Nesil Teknoloji" in html
    assert 'class="badge risk-high"' in html
    assert 'class="badge st-unverified_claim"' in html
    # Doğrulanmamış iddia "ihlal" olarak sunulmaz; kapsam sınırı raporda yazılır.
    assert "erişim izni" in html
    assert "API anahtarı veya gizli yapılandırma bilgisi bulunmaz" in html


def test_export_findings_html_without_findings_shows_notice(repos, settings) -> None:
    exporter = ReportExporter(repos, settings.report_dir)

    html = exporter.export_findings_html([]).read_text(encoding="utf-8")

    assert "Raporlanacak bulgu bulunamadı." in html


def test_findings_to_dicts_scrubs_sensitive_metadata(repos, settings) -> None:
    _store(repos, _finding(metadata={"api_key": "SUPERSECRET-VALUE", "not": "gizli değil"}))
    exporter = ReportExporter(repos, settings.report_dir)

    dicts = exporter.findings_to_dicts(repos.findings.list())
    blob = json.dumps(dicts, ensure_ascii=False)

    assert dicts[0]["metadata"]["api_key"] == "***"
    assert dicts[0]["metadata"]["not"] == "gizli değil"
    assert "SUPERSECRET-VALUE" not in blob


# --------------------------------------------------------------------------- #
# IOC analiz raporları
# --------------------------------------------------------------------------- #
def test_export_analysis_json_reports_source_states(repos, settings) -> None:
    records = [_record(corroborating=["otx", "threatfox"])]
    exporter = ReportExporter(repos, settings.report_dir)

    payload = json.loads(
        exporter.export_analysis_json(_analysis(records, failed=["misp"])).read_text(
            encoding="utf-8"
        )
    )
    analysis = payload["analysis"]

    assert analysis["value"] == "evil.example"
    assert analysis["ioc_type"] == "domain"
    assert analysis["risk_level"] == "high"
    assert analysis["failed_sources"] == ["misp"]
    # Kaynak hatası ile "eşleşme yok" durumu ayrı raporlanır (PRD 7.3).
    states = {source["source_name"]: source["status"] for source in analysis["sources"]}
    assert states == {"otx": "ok", "misp": "error"}
    assert analysis["records"][0]["sources"] == ["otx", "threatfox"]


def test_export_analysis_html_lists_deduplicated_records(repos, settings) -> None:
    exporter = ReportExporter(repos, settings.report_dir)

    html = exporter.export_analysis_html(_analysis([_record(tags=["apt"])])).read_text(
        encoding="utf-8"
    )

    assert "evil.example" in html
    assert "Tekilleştirilmiş kayıtlar (1)" in html
    assert "Tekilleştirme sonrası kayıt bulunamadı." not in html


def test_export_analysis_html_warns_when_a_source_failed(repos, settings) -> None:
    """Kaynak hatası, göstergenin temiz olduğu anlamına gelmez (PRD 19.3)."""
    exporter = ReportExporter(repos, settings.report_dir)

    html = exporter.export_analysis_html(_analysis([], failed=["misp"])).read_text(
        encoding="utf-8"
    )

    assert "temiz olduğu anlamına gelmez" in html
    assert "misp" in html


def test_export_analysis_json_scrubs_sensitive_source_detail(repos, settings) -> None:
    record = _record()
    record.detail["api_key"] = "SUPERSECRET-VALUE"
    exporter = ReportExporter(repos, settings.report_dir)

    blob = exporter.export_analysis_json(_analysis([record])).read_text(encoding="utf-8")

    # Analiz raporu kayıt detayını yazmaz; yine de hassas değer sızmamalıdır.
    assert "SUPERSECRET-VALUE" not in blob


# --------------------------------------------------------------------------- #
# Ortak davranışlar
# --------------------------------------------------------------------------- #
def test_exports_are_written_into_report_dir_and_audited(repos, settings) -> None:
    _store(repos, _finding())
    exporter = ReportExporter(repos, settings.report_dir)

    json_path = exporter.export_findings_json(repos.findings.list())
    html_path = exporter.export_findings_html(repos.findings.list())

    assert json_path.parent == settings.report_dir
    assert html_path.parent == settings.report_dir
    actions = [entry["action"] for entry in repos.audit.list()]
    assert actions.count("report_exported") == 2


def test_export_creates_missing_output_directory(repos, tmp_path) -> None:
    target = tmp_path / "yeni" / "raporlar"
    exporter = ReportExporter(repos, target)

    path = exporter.export_findings_json([])

    assert target.is_dir()
    assert path.exists()


def test_scrub_is_recursive_and_keeps_safe_values() -> None:
    payload = {
        "api_key": "gizli",
        "Authorization": "Bearer gizli",
        "nested": {"token": "gizli", "keep": "açık"},
        "items": [{"secret": "gizli"}, "metin", 3],
    }

    cleaned = scrub(payload)

    assert cleaned["api_key"] == "***"
    assert cleaned["Authorization"] == "***"
    assert cleaned["nested"] == {"token": "***", "keep": "açık"}
    assert cleaned["items"] == [{"secret": "***"}, "metin", 3]
