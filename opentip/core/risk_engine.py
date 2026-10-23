"""Risk ve güven değerlendirme motoru (PRD Bölüm 11).

İki kavram kesin olarak ayrı tutulur:
* **Risk seviyesi** — bulgunun potansiyel etkisi.
* **Doğrulama durumu** — bulgunun kanıtlarla ne ölçüde desteklendiği.

Bu motor yalnızca risk seviyesini üretir; doğrulama durumu `finding_manager`
tarafından ayrı yönetilir. Böylece yüksek etkili ancak doğrulanmamış bir iddia
`high` risk + `unverified_claim` durumunda kalabilir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

from models import (
    Finding,
    FindingType,
    IOCRecord,
    IOCType,
    IOCSourceResult,
    RiskLevel,
)
from .normalizer import to_utc

#: İçsel önem: zararlı yazılım örnek kimlikleri ve URL'ler daha yüksek etkili kabul edilir.
_IOC_TYPE_WEIGHT: dict[IOCType, float] = {
    IOCType.SHA256: 1.0,
    IOCType.SHA1: 1.0,
    IOCType.MD5: 1.0,
    IOCType.URL: 0.7,
    IOCType.IPV4: 0.55,
    IOCType.IPV6: 0.55,
    IOCType.DOMAIN: 0.6,
}

_RISK_SCORE = {
    RiskLevel.UNASSESSED: 0.0,
    RiskLevel.LOW: 0.25,
    RiskLevel.MEDIUM: 0.5,
    RiskLevel.HIGH: 0.8,
    RiskLevel.CRITICAL: 1.0,
}

#: İddia edilen veri türlerinin hassasiyeti (PRD 11).
_DATA_TYPE_SENSITIVITY: dict[str, float] = {
    "credentials": 1.0,
    "kimlik_bilgisi": 1.0,
    "password": 1.0,
    "parola": 1.0,
    "financial": 0.95,
    "finansal": 0.95,
    "credit_card": 0.95,
    "kredi_karti": 0.95,
    "health": 0.9,
    "saglik": 0.9,
    "personal_data": 0.8,
    "kisisel_veri": 0.8,
    "pii": 0.8,
    "contact": 0.5,
    "iletisim": 0.5,
    "source_code": 0.7,
    "kaynak_kod": 0.7,
    "database": 0.85,
    "veritabani": 0.85,
    "customer_data": 0.85,
    "musteri_verisi": 0.85,
}


@dataclass
class RiskFactor:
    """Tek bir değerlendirme faktörü ve gerekçesi."""

    name: str
    points: float
    max_points: float
    reason: str


@dataclass
class RiskAssessment:
    """Risk değerlendirmesi sonucu."""

    level: RiskLevel
    score: float
    reasons: list[str] = field(default_factory=list)
    factors: list[RiskFactor] = field(default_factory=list)
    #: Doğrulama durumunu etkileyebilecek sinyaller (tek kaynak, çelişki vb.)
    verification_notes: list[str] = field(default_factory=list)


class RiskEngine:
    """Ağırlıklı, açıklanabilir risk puanlaması."""

    # Ağırlıklar toplamı 100'dür.
    W_EVIDENCE = 40.0      # gösterge/kaynak beyanı
    W_CORROBORATION = 20.0  # bağımsız kaynak desteği
    W_TYPE = 15.0          # göstergenin içsel önem derecesi
    W_FRESHNESS = 15.0     # güncellik
    W_RELIABILITY = 10.0   # kaynak güvenilirliği

    def assess_ioc(
        self,
        ioc_type: IOCType,
        records: Sequence[IOCRecord],
        source_results: Sequence[IOCSourceResult] = (),
        source_reliability: Optional[float] = None,
    ) -> RiskAssessment:
        """Bir IOC sorgusunun sonuçlarını değerlendirir."""
        factors: list[RiskFactor] = []
        notes: list[str] = []

        if not records:
            return RiskAssessment(
                level=RiskLevel.UNASSESSED,
                score=0.0,
                reasons=["Hiçbir kaynakta eşleşme bulunamadı."],
                factors=[],
                verification_notes=["Eşleşme yokluğu, göstergenin temiz olduğu anlamına gelmez."],
            )

        # 1) Kanıtın ağırlığı — kaynakların bildirdiği en yüksek risk seviyesi
        strongest = max(records, key=lambda r: _RISK_SCORE.get(r.risk_level, 0.0))
        strongest_value = _RISK_SCORE.get(strongest.risk_level, 0.0)
        max_confidence = max((r.confidence or 0.0) for r in records)
        evidence_ratio = min(1.0, strongest_value * 0.7 + max_confidence * 0.3)
        factors.append(
            RiskFactor(
                "kaynak_beyani",
                round(self.W_EVIDENCE * evidence_ratio, 2),
                self.W_EVIDENCE,
                f"En yüksek kaynak beyanı: {strongest.risk_level} "
                f"({strongest.source_name}), güven={max_confidence:.2f}",
            )
        )

        # 2) Bağımsız kaynak desteği
        distinct_sources = {r.source_name for r in records}
        corroboration_ratio = {1: 0.35, 2: 0.7}.get(len(distinct_sources), 1.0)
        factors.append(
            RiskFactor(
                "bagimsiz_destek",
                round(self.W_CORROBORATION * corroboration_ratio, 2),
                self.W_CORROBORATION,
                f"Bildiren bağımsız kaynak sayısı: {len(distinct_sources)}",
            )
        )
        if len(distinct_sources) == 1:
            notes.append("Tek kaynak beyanı; bağımsız destek yok.")

        # 3) Gösterge türünün içsel önemi
        type_ratio = _IOC_TYPE_WEIGHT.get(ioc_type, 0.5)
        factors.append(
            RiskFactor(
                "gosterge_turu",
                round(self.W_TYPE * type_ratio, 2),
                self.W_TYPE,
                f"Gösterge türü: {ioc_type}",
            )
        )

        # 4) Güncellik
        latest = max(r.last_seen for r in records)
        age_days = (datetime.now(timezone.utc) - to_utc(latest)).days
        if age_days <= 30:
            freshness_ratio, freshness_text = 1.0, f"Son görülme {age_days} gün önce"
        elif age_days <= 90:
            freshness_ratio, freshness_text = 0.6, f"Son görülme {age_days} gün önce"
        else:
            freshness_ratio, freshness_text = 0.25, f"Kayıt eski ({age_days} gün)"
        factors.append(
            RiskFactor(
                "guncellik",
                round(self.W_FRESHNESS * freshness_ratio, 2),
                self.W_FRESHNESS,
                freshness_text,
            )
        )

        # 5) Kaynak güvenilirliği
        # Kaynak güvenilirliği verilmezse nötr (0.5) kabul edilir.
        reliability = 0.5 if source_reliability is None else float(source_reliability)
        reliability = max(0.0, min(1.0, reliability))
        factors.append(
            RiskFactor(
                "kaynak_guvenilirligi",
                round(self.W_RELIABILITY * reliability, 2),
                self.W_RELIABILITY,
                f"Kaynak güvenilirlik katsayısı: {reliability:.2f}",
            )
        )

        failed = [r.source_name for r in source_results if r.has_error]
        if failed:
            notes.append(
                "Bazı kaynaklar yanıt vermedi (" + ", ".join(failed) + "); sonuç eksik olabilir."
            )

        return self._finalize(factors, notes)

    def assess_finding(
        self,
        finding: Finding,
        evidence_count: int = 0,
        independent_sources: int = 1,
        association_verified: bool = False,
    ) -> RiskAssessment:
        """Sızıntı / Dark Web bulgularını değerlendirir."""
        factors: list[RiskFactor] = []
        notes: list[str] = []

        # 1) İddia edilen veri türü hassasiyeti
        sensitivity = self._max_sensitivity(finding.claimed_data_types)
        factors.append(
            RiskFactor(
                "veri_hassasiyeti",
                25.0 * sensitivity,
                25.0,
                f"İddia edilen veri türleri: {', '.join(finding.claimed_data_types) or 'belirtilmemiş'}",
            )
        )

        # 2) Bağımsız kaynak desteği
        corroboration_ratio = {1: 0.2, 2: 0.6}.get(independent_sources, 1.0)
        factors.append(
            RiskFactor(
                "bagimsiz_destek",
                25.0 * corroboration_ratio,
                25.0,
                f"Bağımsız kaynak sayısı: {independent_sources}",
            )
        )
        if independent_sources <= 1:
            notes.append("Tek kaynaklı iddia; doğrulama için bağımsız destek gerekir.")

        # 3) Kurumla ilişkilendirme doğruluğu
        association_ratio = 1.0 if association_verified else 0.4
        factors.append(
            RiskFactor(
                "iliskilendirme",
                20.0 * association_ratio,
                20.0,
                "Doğrulanmış varlık eşleşmesi"
                if association_verified
                else "Yalnızca isim/marka benzerliği ile eşleşme",
            )
        )
        if not association_verified:
            notes.append("İlişkilendirme doğrulanmış bir varlığa dayanmıyor; yanlış eşleşme olabilir.")

        # 4) Kanıt niteliği
        evidence_ratio = min(1.0, evidence_count / 3.0)
        factors.append(
            RiskFactor(
                "kanit_niteligi",
                15.0 * evidence_ratio,
                15.0,
                f"Kayıtlı kanıt referansı sayısı: {evidence_count}",
            )
        )

        # 5) Kaynak güvenilirliği
        reliability = finding.source_reliability if finding.source_reliability is not None else 0.5
        reliability = max(0.0, min(1.0, float(reliability)))
        factors.append(
            RiskFactor(
                "kaynak_guvenilirligi",
                15.0 * reliability,
                15.0,
                f"Kaynak güvenilirlik katsayısı: {reliability:.2f}",
            )
        )

        return self._finalize(factors, notes)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _max_sensitivity(data_types: Sequence[str]) -> float:
        if not data_types:
            return 0.3  # bilinmeyen veri türü: düşük-orta varsayım
        values = []
        for data_type in data_types:
            key = str(data_type).strip().lower().replace(" ", "_")
            values.append(_DATA_TYPE_SENSITIVITY.get(key, 0.45))
        return max(values)

    @staticmethod
    def _finalize(factors: list[RiskFactor], notes: list[str]) -> RiskAssessment:
        score = round(min(100.0, sum(f.points for f in factors)), 1)
        if score >= 75:
            level = RiskLevel.CRITICAL
        elif score >= 55:
            level = RiskLevel.HIGH
        elif score >= 35:
            level = RiskLevel.MEDIUM
        elif score > 0:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.UNASSESSED

        reasons = [f"{f.reason} (+{f.points:.1f}/{f.max_points:.0f})" for f in factors]
        reasons.append(f"Toplam risk puanı: {score}/100 → {level}")
        return RiskAssessment(
            level=level, score=score, reasons=reasons, factors=factors, verification_notes=notes
        )
