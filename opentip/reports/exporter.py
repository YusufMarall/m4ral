"""JSON ve HTML rapor dışa aktarma (PRD 13, 19.12).

Raporlar API anahtarı veya gizli yapılandırma içermez. Sızdırılmış hassas veri
gövdesi saklanmadığı için raporlara da dahil edilmez; yalnızca kaynak referansı
ve kanıt özeti yazılır.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from models import AnalysisResult, Finding
from storage import Repositories

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
DEFAULT_TEMPLATE = "report.html.j2"

#: Raporlarda asla yer almaması gereken alan adları.
SENSITIVE_KEYS = {"api_key", "apikey", "token", "password", "secret", "authorization", "auth-key"}


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def scrub(value: Any) -> Any:
    """Raporlanacak veriden hassas anahtarları temizler (savunma amaçlı)."""
    if isinstance(value, dict):
        return {
            key: ("***" if str(key).lower() in SENSITIVE_KEYS else scrub(item))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [scrub(item) for item in value]
    return value


class ReportExporter:
    """Rapor üretiminden sorumludur."""

    def __init__(self, repos: Repositories, output_dir: Path) -> None:
        self.repos = repos
        self.output_dir = Path(output_dir).expanduser()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Bulgu raporları
    # ------------------------------------------------------------------ #
    def findings_to_dicts(self, findings: Iterable[Finding]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for finding in findings:
            data = scrub(finding.model_dump(mode="json"))
            data["target"] = finding.organization or finding.matched_domain or finding.ioc_value
            result.append(data)
        return result

    def export_findings_json(
        self,
        findings: Sequence[Finding],
        filename: Optional[str] = None,
        title: str = "OpenTIP Bulgu Raporu",
    ) -> Path:
        payload = {
            "report": title,
            "generated_at": _iso_now(),
            "finding_count": len(findings),
            "stats": self.repos.findings.stats(),
            "findings": [f.to_public_dict() | {"target": f.organization or f.matched_domain or f.ioc_value}
                         for f in findings],
        }
        path = self.output_dir / (filename or f"opentip_findings_{_timestamp()}.json")
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        self.repos.audit.log(
            "report_exported", entity_type="report", entity_id=path.name, detail={"format": "json"}
        )
        return path

    def export_findings_html(
        self,
        findings: Sequence[Finding],
        filename: Optional[str] = None,
        title: str = "OpenTIP Bulgu Raporu",
        notice: Optional[str] = None,
    ) -> Path:
        stats = self.repos.findings.stats()
        context = {
            "title": title,
            "generated_at": _iso_now(),
            "stats": {
                "Toplam bulgu": stats["total"],
                "Kritik": stats["by_risk"].get("critical", 0),
                "Yüksek": stats["by_risk"].get("high", 0),
                "İnceleme bekleyen": sum(
                    stats["by_status"].get(status, 0)
                    for status in ("new", "under_review", "unverified_claim")
                ),
            },
            "findings": self.findings_to_dicts(findings),
            "analysis": None,
            "notice": notice,
        }
        path = self.output_dir / (filename or f"opentip_findings_{_timestamp()}.html")
        path.write_text(self._render(context), encoding="utf-8")
        self.repos.audit.log(
            "report_exported", entity_type="report", entity_id=path.name, detail={"format": "html"}
        )
        return path

    # ------------------------------------------------------------------ #
    # IOC analiz raporları
    # ------------------------------------------------------------------ #
    def analysis_to_dict(self, analysis: AnalysisResult) -> dict[str, Any]:
        return {
            "value": analysis.value,
            "ioc_type": str(analysis.ioc_type),
            "started_at": analysis.started_at.isoformat(),
            "finished_at": analysis.finished_at.isoformat() if analysis.finished_at else None,
            "risk_level": str(analysis.risk_level),
            "risk_score": analysis.risk_score,
            "risk_reasons": analysis.risk_reasons,
            "notes": analysis.notes,
            "queried_sources": analysis.queried_sources,
            "failed_sources": analysis.failed_sources,
            #: Şablon, kayıt tablosunu yalnızca bu alan doluyken çizer.
            "record_count": len(analysis.deduplicated_records),
            "records": [
                {
                    "value": record.value,
                    "ioc_type": str(record.ioc_type),
                    "risk_level": str(record.risk_level),
                    "confidence": record.confidence,
                    "first_seen": record.first_seen.isoformat(),
                    "last_seen": record.last_seen.isoformat(),
                    "tags": record.tags,
                    "sources": [
                        s.get("source_name") for s in (record.detail.get("sources") or [])
                    ],
                }
                for record in analysis.deduplicated_records
            ],
            "sources": [
                {
                    "source_name": result.source_name,
                    "status": str(result.status),
                    "record_count": len(result.records),
                    "error": result.error,
                    "duration_ms": result.duration_ms,
                    "checked_at": result.checked_at.isoformat(),
                }
                for result in analysis.source_results
            ],
        }

    def export_analysis_json(self, analysis: AnalysisResult, filename: Optional[str] = None) -> Path:
        payload = {
            "report": "OpenTIP IOC Analiz Raporu",
            "generated_at": _iso_now(),
            "analysis": self.analysis_to_dict(analysis),
        }
        path = self.output_dir / (filename or f"opentip_ioc_{_timestamp()}.json")
        path.write_text(json.dumps(scrub(payload), ensure_ascii=False, indent=2), encoding="utf-8")
        self.repos.audit.log(
            "report_exported", entity_type="report", entity_id=path.name, detail={"format": "json"}
        )
        return path

    def export_analysis_html(
        self, analysis: AnalysisResult, filename: Optional[str] = None
    ) -> Path:
        context = {
            "title": "OpenTIP IOC Analiz Raporu",
            "generated_at": _iso_now(),
            "stats": None,
            "analysis": self.analysis_to_dict(analysis),
            "findings": [],
            "notice": (
                "Bir kaynağın yanıt vermemesi, göstergenin temiz olduğu anlamına gelmez. "
                "Kaynak durumlarını ayrıca değerlendirin."
                if analysis.failed_sources
                else None
            ),
        }
        path = self.output_dir / (filename or f"opentip_ioc_{_timestamp()}.html")
        path.write_text(self._render(context), encoding="utf-8")
        self.repos.audit.log(
            "report_exported", entity_type="report", entity_id=path.name, detail={"format": "html"}
        )
        return path

    # ------------------------------------------------------------------ #
    def _render(self, context: dict[str, Any]) -> str:
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        return env.get_template(DEFAULT_TEMPLATE).render(**context)
