"""Uygulama içi alarm ve bildirim üretimi (PRD Bölüm 12).

MVP'de bildirimler yalnızca uygulama içi alarm olarak gösterilir. E-posta veya
kurumsal bildirim kanalları sonraki sürümlere bırakılmıştır.

Alarmlar; kaynak referansı, tespit zamanı, bulgu türü ve doğrulama durumu
içermelidir. Tekrarlanan kayıtlar yeni alarm üretmez (PRD 9.5).
"""

from __future__ import annotations

from typing import Optional, Sequence

from models import (
    Alert,
    Finding,
    FindingType,
    RiskLevel,
    SourceStatus,
    VerificationStatus,
)
from storage import Repositories

#: Alarm türleri
ALERT_NEW_FINDING = "new_finding"
ALERT_FINDING_CHANGED = "finding_changed"
ALERT_STATUS_CHANGED = "status_changed"
ALERT_SOURCE_FAILURE = "source_failure"
ALERT_SOURCE_RECOVERED = "source_recovered"
ALERT_HIGH_RISK = "high_risk_finding"

#: Kaynak bu sayıda ardışık kez başarısız olursa alarm üretilir.
DEFAULT_FAILURE_THRESHOLD = 3


class NotificationService:
    """Alarm üretimini merkezi olarak yönetir."""

    def __init__(
        self,
        repos: Repositories,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
    ) -> None:
        self.repos = repos
        self.failure_threshold = failure_threshold

    # ------------------------------------------------------------------ #
    # Bulgu kaynaklı alarmlar
    # ------------------------------------------------------------------ #
    def on_new_finding(self, finding: Finding) -> Optional[Alert]:
        """Yeni bulgu için alarm. Yüksek/kritik risk ayrıca işaretlenir."""
        if not self._organization_notifications_enabled(finding):
            return None

        alert = Alert(
            alert_type=ALERT_NEW_FINDING,
            severity=finding.risk_level,
            finding_id=finding.finding_id,
            source_name=finding.source_name,
            title=f"Yeni bulgu: {finding.finding_type} [{finding.risk_level}]",
            message=(
                f"Kaynak: {finding.source_name} ({finding.source_type}); "
                f"doğrulama: {finding.verification_status}; "
                f"hedef: {finding.organization or finding.matched_domain or finding.ioc_value}; "
                f"referans: {finding.source_reference or '-'}"
            ),
        )
        alert_id = self.repos.alerts.create(alert)
        alert.alert_id = alert_id
        self.repos.findings.mark_notified(finding.finding_id)

        if finding.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            high = Alert(
                alert_type=ALERT_HIGH_RISK,
                severity=finding.risk_level,
                finding_id=finding.finding_id,
                source_name=finding.source_name,
                title=f"Yüksek riskli bulgu: {finding.risk_level}",
                message=f"Risk gerekçeleri: {'; '.join(finding.risk_reasons[:4]) or 'belirtilmemiş'}",
            )
            high.alert_id = self.repos.alerts.create(high)
        return alert

    def on_finding_changed(self, finding: Finding, changed_fields: Sequence[str]) -> Optional[Alert]:
        """Bilinen bulgunun önemli ölçüde değişmesi."""
        if not changed_fields:
            return None
        if not self._organization_notifications_enabled(finding):
            return None

        alert = Alert(
            alert_type=ALERT_FINDING_CHANGED,
            severity=finding.risk_level,
            finding_id=finding.finding_id,
            source_name=finding.source_name,
            title=f"Bulgu güncellendi: {', '.join(changed_fields)}",
            message=(
                f"{finding.finding_id} kaydında değişiklik: {', '.join(changed_fields)}. "
                f"Doğrulama durumu: {finding.verification_status}."
            ),
        )
        alert.alert_id = self.repos.alerts.create(alert)
        return alert

    def on_status_change(
        self,
        finding: Finding,
        previous: VerificationStatus,
        current: VerificationStatus,
    ) -> Optional[Alert]:
        alert = Alert(
            alert_type=ALERT_STATUS_CHANGED,
            severity=finding.risk_level,
            finding_id=finding.finding_id,
            source_name=finding.source_name,
            title=f"Doğrulama durumu değişti: {previous} → {current}",
            message=f"{finding.finding_id} için doğrulama durumu güncellendi.",
        )
        alert.alert_id = self.repos.alerts.create(alert)
        return alert

    # ------------------------------------------------------------------ #
    # Kaynak kaynaklı alarmlar
    # ------------------------------------------------------------------ #
    def on_source_error(self, source_name: str, message: str) -> Optional[Alert]:
        """Kaynak uzun süre başarısız olduğunda tek seferlik alarm üretir."""
        health = self.repos.sources.health(source_name)
        failures = health.consecutive_failures if health else 1
        if failures < self.failure_threshold:
            return None
        # Aynı kaynak için açık bir hata alarmı varsa tekrar üretilmez.
        open_alerts = [
            a
            for a in self.repos.alerts.list(unacknowledged_only=True, limit=200)
            if a.alert_type == ALERT_SOURCE_FAILURE and a.source_name == source_name
        ]
        if open_alerts:
            return None

        alert = Alert(
            alert_type=ALERT_SOURCE_FAILURE,
            severity=RiskLevel.MEDIUM,
            source_name=source_name,
            title=f"Kaynak erişilemiyor: {source_name}",
            message=(
                f"{source_name} kaynağı {failures} kez üst üste başarısız oldu. "
                f"Son hata: {message}. Son başarılı kontrol korunuyor."
            ),
        )
        alert.alert_id = self.repos.alerts.create(alert)
        return alert

    def on_source_recovered(self, source_name: str) -> Optional[Alert]:
        alert = Alert(
            alert_type=ALERT_SOURCE_RECOVERED,
            severity=RiskLevel.LOW,
            source_name=source_name,
            title=f"Kaynak bağlantısı yeniden kuruldu: {source_name}",
            message=f"{source_name} kaynağı yeniden başarılı yanıt veriyor.",
        )
        alert.alert_id = self.repos.alerts.create(alert)
        return alert

    def notify_source_status(
        self, source_name: str, status: SourceStatus, message: str = "", was_failing: bool = False
    ) -> Optional[Alert]:
        """Kaynak durumuna göre uygun alarmı üretir."""
        if status in (SourceStatus.ERROR, SourceStatus.UNAVAILABLE):
            return self.on_source_error(source_name, message)
        if status == SourceStatus.OK and was_failing:
            return self.on_source_recovered(source_name)
        return None

    # ------------------------------------------------------------------ #
    def list_alerts(self, limit: int = 100, unacknowledged_only: bool = False) -> list[Alert]:
        return self.repos.alerts.list(limit=limit, unacknowledged_only=unacknowledged_only)

    def acknowledge(self, alert_id: int) -> None:
        self.repos.alerts.acknowledge(alert_id)

    def acknowledge_all(self) -> None:
        self.repos.alerts.acknowledge_all()

    def open_count(self) -> int:
        return self.repos.alerts.open_count()

    # ------------------------------------------------------------------ #
    def _organization_notifications_enabled(self, finding: Finding) -> bool:
        """Kurum profili bildirimleri kapatmışsa alarm üretilmez."""
        if not finding.organization_id:
            return True
        org = self.repos.organizations.get(finding.organization_id)
        if org is None:
            return True
        return bool(org.get("notifications_enabled", True))


def is_actionable_finding(finding: Finding) -> bool:
    """Bulgunun analist müdahalesi gerektirip gerektirmediği."""
    return finding.verification_status in (
        VerificationStatus.NEW,
        VerificationStatus.UNDER_REVIEW,
        VerificationStatus.UNVERIFIED_CLAIM,
    ) and finding.finding_type in (
        FindingType.BREACH_CLAIM,
        FindingType.DARKWEB_RECORD,
        FindingType.IOC_MATCH,
    )
