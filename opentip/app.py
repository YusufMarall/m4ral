"""OpenTIP — Open Threat Intelligence Platform (Streamlit arayüzü).

Çalıştırma:
    streamlit run app.py

Arayüz; IOC analizi, sızıntı istihbaratı, izinli kaynak izleme ve raporlamayı
tek panelde birleştirir. Hiçbir modül tüm Dark Web'i taradığını iddia etmez;
yalnızca gerçekten kontrol edilen kapsam gösterilir.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Optional

import streamlit as st

from adapters import (
    build_adapters_from_repos,
    build_deepdarkcti_adapter,
    sync_sources,
    update_source_settings,
)
from config import get_settings
from core import (
    DEEPDARK_CATEGORIES,
    AnalysisManager,
    DeepDarkCatalogService,
    FindingManager,
    IOCValidationError,
    RiskEngine,
    validate_ioc,
)
from monitoring import MonitoringScheduler, NotificationService, SourceMonitor
from models import (
    CatalogNetwork,
    CatalogStatus,
    Evidence,
    Finding,
    FindingType,
    IOCType,
    RiskLevel,
    SourceStatus,
    SourceType,
    VerificationStatus,
    utcnow,
)
from reports import ReportExporter
from storage import Repositories

# --------------------------------------------------------------------------- #
# Uygulama iskeleti
# --------------------------------------------------------------------------- #
st.set_page_config(page_title="OpenTIP", page_icon="🛡️", layout="wide")

RISK_ORDER = ["critical", "high", "medium", "low", "unassessed"]
RISK_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "unassessed": "⚪",
}
STATUS_LABELS = {
    "new": "Yeni",
    "under_review": "İncelemede",
    "unverified_claim": "Doğrulanmamış iddia",
    "corroborated": "Destekleniyor",
    "confirmed": "Doğrulandı",
    "false_positive": "Yanlış pozitif",
    "closed": "Kapatıldı",
}
TYPE_LABELS = {
    "ioc_match": "IOC eşleşmesi",
    "breach_claim": "Sızıntı iddiası",
    "darkweb_record": "Dark Web kaydı",
}
NETWORK_LABELS = {"tor": "Tor (onion)", "clearnet": "Clearnet", "unknown": "Bilinmiyor"}
CATALOG_STATUS_LABELS = {"online": "Çevrimiçi", "offline": "Çevrimdışı", "unknown": "Bilinmiyor"}
ASSET_TYPES = ["domain", "email_domain", "brand", "alias", "keyword", "legal_id"]


@dataclass
class AppContext:
    """Uygulama bileşenlerinin tek noktadan erişimi."""

    settings: Any
    repos: Repositories
    finder: FindingManager
    analyzer: AnalysisManager
    monitor: SourceMonitor
    notifier: NotificationService
    exporter: ReportExporter
    scheduler: MonitoringScheduler
    catalog: DeepDarkCatalogService

    def refresh_adapters(self) -> None:
        """Veritabanındaki yapılandırmaya göre adaptörleri yeniden kurar."""
        adapters = build_adapters_from_repos(self.repos, self.settings)
        self.analyzer.set_adapters(adapters)
        self.monitor.adapters = {a.name: a for a in adapters}


@st.cache_resource(show_spinner=False)
def bootstrap() -> AppContext:
    """Uygulama bileşenlerini tek seferlik kurar."""
    settings = get_settings()
    repos = Repositories.from_settings(settings)
    sync_sources(repos, settings)

    notifier = NotificationService(repos)
    risk_engine = RiskEngine()
    finder = FindingManager(repos, risk_engine, notifier)
    adapters = build_adapters_from_repos(repos, settings)
    analyzer = AnalysisManager(repos, adapters, risk_engine, finder)
    monitor = SourceMonitor(repos, adapters, finder, notifier)
    exporter = ReportExporter(repos, settings.report_dir)
    scheduler = MonitoringScheduler(monitor)
    catalog = DeepDarkCatalogService(repos, build_deepdarkcti_adapter(settings))

    return AppContext(
        settings=settings,
        repos=repos,
        finder=finder,
        analyzer=analyzer,
        monitor=monitor,
        notifier=notifier,
        exporter=exporter,
        scheduler=scheduler,
        catalog=catalog,
    )


def fmt(value: Optional[datetime]) -> str:
    if value is None:
        return "-"
    return value.strftime("%Y-%m-%d %H:%M")


def risk_badge(level: Any) -> str:
    key = str(level)
    return f"{RISK_ICONS.get(key, '⚪')} {key}"


def status_badge(status: Any) -> str:
    key = str(status)
    return STATUS_LABELS.get(key, key)


# --------------------------------------------------------------------------- #
# Ortak bileşenler
# --------------------------------------------------------------------------- #
def finding_rows(findings: list[Finding]) -> list[dict[str, Any]]:
    return [
        {
            "ID": f.finding_id,
            "Tür": TYPE_LABELS.get(str(f.finding_type), str(f.finding_type)),
            "Hedef": f.organization or f.matched_domain or f.ioc_value or "-",
            "Kaynak": f.source_name,
            "Referans": f.source_reference or "-",
            "Risk": risk_badge(f.risk_level),
            "Doğrulama": status_badge(f.verification_status),
            "Son kontrol": fmt(f.last_checked),
        }
        for f in findings
    ]


def render_finding_detail(ctx: AppContext, finding: Finding, key_prefix: str = "") -> None:
    """Tek bir bulgunun ayrıntı, kanıt, not ve durum yönetimi."""
    st.markdown(f"#### {finding.finding_id} — {TYPE_LABELS.get(str(finding.finding_type))}")
    cols = st.columns(4)
    cols[0].metric("Risk", risk_badge(finding.risk_level), f"{finding.risk_score or 0}/100")
    cols[1].metric("Doğrulama", status_badge(finding.verification_status))
    cols[2].metric("İlk görülme", fmt(finding.first_seen))
    cols[3].metric("Son kontrol", fmt(finding.last_checked))

    st.write(
        f"**Kaynak:** {finding.source_name} (`{finding.source_type}`) &nbsp;|&nbsp; "
        f"**Referans:** `{finding.source_reference or '-'}` &nbsp;|&nbsp; "
        f"**Hedef:** {finding.organization or finding.matched_domain or '-'}"
    )
    if finding.claimed_data_types:
        st.write("**İddia edilen veri türleri:** " + ", ".join(finding.claimed_data_types))
    st.info(finding.evidence_summary or "Kanıt özeti bulunmuyor.")

    if finding.risk_reasons:
        with st.expander("Risk gerekçeleri", expanded=False):
            for reason in finding.risk_reasons:
                st.write(f"- {reason}")

    association = finding.metadata.get("association_reasons")
    if association:
        with st.expander("Kurumla ilişkilendirme gerekçeleri"):
            for reason in association:
                st.write(f"- {reason}")

    verification_notes = finding.metadata.get("verification_notes")
    if verification_notes:
        st.warning(" ".join(verification_notes))

    details = ctx.finder.details(finding.finding_id) or {}
    evidence = details.get("evidence") or []
    notes = details.get("notes") or []

    left, right = st.columns(2)
    with left:
        st.write(f"**Kanıt referansları ({len(evidence)})**")
        if evidence:
            st.dataframe(
                [
                    {
                        "Kaynak": e.source_name,
                        "Referans": e.source_reference or "-",
                        "Toplanma": fmt(e.collected_at),
                        "Özet": (e.summary or "")[:160],
                    }
                    for e in evidence
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption("Kanıt kaydı yok.")
    with right:
        st.write(f"**Analist notları ({len(notes)})**")
        for note in notes[:5]:
            st.caption(f"{fmt(note.created_at)} · {note.author}: {note.note}")

    # Durum güncelleme
    allowed = [s for s in VerificationStatus]
    with st.form(f"{key_prefix}status_form_{finding.finding_id}"):
        target = st.selectbox(
            "Doğrulama durumu",
            allowed,
            index=allowed.index(VerificationStatus(finding.verification_status)),
            format_func=lambda s: f"{STATUS_LABELS.get(str(s), str(s))} ({s})",
            key=f"{key_prefix}status_{finding.finding_id}",
        )
        note = st.text_input("Not (opsiyonel)", key=f"{key_prefix}note_{finding.finding_id}")
        submitted = st.form_submit_button("Durumu güncelle")
        if submitted:
            try:
                ctx.finder.set_status(finding.finding_id, target, note=note or None)
                st.success("Durum güncellendi.")
                st.rerun()
            except ValueError as exc:
                st.error(f"Geçersiz geçiş: {exc}")

    with st.form(f"{key_prefix}note_form_{finding.finding_id}"):
        new_note = st.text_area("Yeni analist notu", key=f"{key_prefix}newnote_{finding.finding_id}")
        if st.form_submit_button("Not ekle") and new_note.strip():
            ctx.finder.add_note(finding.finding_id, new_note.strip())
            st.success("Not eklendi.")
            st.rerun()


# --------------------------------------------------------------------------- #
# Sayfa: Dashboard
# --------------------------------------------------------------------------- #
def page_dashboard(ctx: AppContext) -> None:
    st.title("📊 Dashboard")
    stats = ctx.repos.findings.stats()
    pending = ctx.finder.pending_review(limit=50)
    health = ctx.repos.sources.health_all()
    open_alerts = ctx.notifier.list_alerts(limit=50, unacknowledged_only=True)

    cols = st.columns(5)
    cols[0].metric("Toplam bulgu", stats["total"])
    cols[1].metric("Kritik", stats["by_risk"].get("critical", 0))
    cols[2].metric("Yüksek", stats["by_risk"].get("high", 0))
    cols[3].metric("İnceleme bekleyen", len(pending))
    cols[4].metric("Açık alarm", len(open_alerts))

    st.subheader("Kaynakların çalışma durumu")
    if health:
        st.dataframe(
            [
                {
                    "Kaynak": h.source_name,
                    "Durum": "🟢 ok" if h.status == SourceStatus.OK else f"🔴 {h.status}",
                    "Etkin": "evet" if h.enabled else "hayır",
                    "Son kontrol": fmt(h.last_checked_at),
                    "Son başarı": fmt(h.last_success_at),
                    "Ardışık hata": h.consecutive_failures,
                    "Sıklık (dk)": h.check_interval_minutes,
                    "Mesaj": h.message,
                }
                for h in health
            ],
            use_container_width=True,
            hide_index=True,
        )
        failing = [h.source_name for h in health if h.consecutive_failures >= 1]
        if failing:
            st.warning(
                "Yanıt vermeyen kaynaklar: "
                + ", ".join(failing)
                + ". Son başarılı kontrol zamanı korunmaktadır; bu durum eşleşme yokluğu anlamına gelmez."
            )
    else:
        st.caption("Kaynak yapılandırması bulunmuyor.")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("İnceleme bekleyen iddialar")
        if pending:
            st.dataframe(finding_rows(pending), use_container_width=True, hide_index=True)
        else:
            st.caption("İnceleme bekleyen kayıt yok.")
    with right:
        st.subheader("Açık alarmlar")
        for alert in open_alerts[:15]:
            with st.container(border=True):
                st.write(f"**{alert.title}**")
                st.caption(f"{fmt(alert.created_at)} · {alert.source_name or '-'} · {alert.alert_type}")
                st.write(alert.message)
                if st.button("Onayla", key=f"ack_{alert.alert_id}"):
                    ctx.notifier.acknowledge(alert.alert_id or 0)
                    st.rerun()
        if open_alerts and st.button("Tüm alarmları onayla"):
            ctx.notifier.acknowledge_all()
            st.rerun()
        if not open_alerts:
            st.caption("Açık alarm yok.")

    st.subheader("Son IOC kayıtları")
    recent_iocs = ctx.repos.iocs.recent(limit=15)
    if recent_iocs:
        st.dataframe(
            [
                {
                    "Gösterge": r["value"],
                    "Tür": str(r["ioc_type"]),
                    "Kaynak": r["source_name"],
                    "Risk": risk_badge(r["risk_level"]),
                    "Son görülme": fmt(r["last_seen"]),
                }
                for r in recent_iocs
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.caption("Henüz IOC kaydı yok. 'IOC Analysis' sayfasından analiz başlatabilirsiniz.")

    st.subheader("Son zamanlanmış kontroller")
    runs = ctx.repos.source_runs.list_recent(limit=10)
    if runs:
        st.dataframe(
            [
                {
                    "Kaynak": r.source_name,
                    "Başlangıç": fmt(r.started_at),
                    "Durum": str(r.status),
                    "Kayıt": r.records_fetched,
                    "Yeni bulgu": r.findings_created,
                    "Güncelleme": r.findings_updated,
                    "Tetikleyen": r.triggered_by,
                }
                for r in runs
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.caption("Henüz kontrol çalışması yok.")


# --------------------------------------------------------------------------- #
# Sayfa: IOC Analysis
# --------------------------------------------------------------------------- #
def page_ioc(ctx: AppContext) -> None:
    st.title("🔎 IOC Analysis")
    st.caption(
        "Desteklenen göstergeler: IPv4, IPv6, domain, URL, MD5, SHA-1, SHA-256. "
        "Savunmasızlaştırılmış girdiler (örn. `185[.]220[.]101[.]5`) otomatik düzeltilir."
    )

    adapters = ctx.analyzer.ioc_adapters()
    available = [a.name for a in adapters]
    configured = [c.name for c in ctx.repos.sources.list() if c.source_type == SourceType.IOC_FEED]

    if not available:
        st.warning(
            "Etkin ve IOC sorgusunu destekleyen bir kaynak yok. "
            "`.env` dosyasında ilgili kaynağı etkinleştirin veya 'Dark Web & Sources' sayfasından açın."
        )

    with st.form("ioc_form"):
        col1, col2 = st.columns([3, 2])
        value = col1.text_input("Gösterge", placeholder="örn. example.com, 8.8.8.8, 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        declared = col2.selectbox(
            "Tür (opsiyonel)", ["otomatik"] + [str(t) for t in IOCType], index=0
        )
        selected_sources = st.multiselect(
            "Sorgulanacak kaynaklar",
            available,
            default=available,
            help="Yalnızca etkin ve IOC sorgusunu destekleyen kaynaklar listelenir.",
        )
        persist = st.checkbox("Sonuçları veritabanına kaydet", value=True)
        submitted = st.form_submit_button("Analiz et", type="primary")

    if submitted:
        if not value.strip():
            st.error("Bir gösterge girin.")
            return
        try:
            parsed = validate_ioc(value, None if declared == "otomatik" else IOCType(declared))
        except IOCValidationError as exc:
            st.error(str(exc))
            return

        with st.spinner("Kaynaklar sorgulanıyor…"):
            try:
                analysis = ctx.analyzer.analyze_ioc(
                    parsed.value or value,
                    declared_type=parsed.ioc_type,
                    adapter_names=selected_sources or None,
                    persist=persist,
                )
            except IOCValidationError as exc:
                st.error(str(exc))
                return
        st.session_state["last_analysis"] = analysis

    analysis = st.session_state.get("last_analysis")
    if analysis is None:
        if configured and not available:
            st.info("Kaynaklar yapılandırılmış ancak etkin değil: " + ", ".join(configured))
        return

    st.divider()
    st.subheader("Sonuç")
    cols = st.columns(4)
    cols[0].metric("Gösterge", analysis.value)
    cols[1].metric("Tür", str(analysis.ioc_type))
    cols[2].metric("Risk", risk_badge(analysis.risk_level))
    cols[3].metric("Risk puanı", f"{analysis.risk_score or 0}/100")

    st.write(f"**Sorgulanan kaynaklar:** {', '.join(analysis.queried_sources) or 'yok'}")
    if analysis.failed_sources:
        st.error(
            "Yanıt vermeyen kaynaklar: "
            + ", ".join(analysis.failed_sources)
            + ". Bu durum göstergenin temiz olduğu anlamına gelmez."
        )

    st.write("**Kaynak bazında sonuçlar**")
    st.dataframe(
        [
            {
                "Kaynak": r.source_name,
                "Durum": ("🔴 " if r.has_error else "🟢 ") + str(r.status),
                "Eşleşme": len(r.records),
                "Hata": r.error or "-",
                "Süre (ms)": r.duration_ms if r.duration_ms is not None else "-",
            }
            for r in analysis.source_results
        ],
        use_container_width=True,
        hide_index=True,
    )

    if analysis.deduplicated_records:
        st.write(f"**Tekilleştirilmiş kayıtlar ({len(analysis.deduplicated_records)})**")
        st.dataframe(
            [
                {
                    "Gösterge": r.value,
                    "Tür": str(r.ioc_type),
                    "Risk": risk_badge(r.risk_level),
                    "Güven": r.confidence,
                    "Etiketler": ", ".join(r.tags[:6]),
                    "Kaynaklar": ", ".join(
                        s.get("source_name", "") for s in (r.detail.get("sources") or [])
                    ),
                    "Son görülme": fmt(r.last_seen),
                }
                for r in analysis.deduplicated_records
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Hiçbir kaynakta eşleşme bulunamadı.")

    with st.expander("Risk gerekçeleri", expanded=True):
        for reason in analysis.risk_reasons:
            st.write(f"- {reason}")
        for note in analysis.notes:
            st.caption(note)

    col_a, col_b = st.columns(2)
    json_path = ctx.exporter.export_analysis_json(analysis)
    html_path = ctx.exporter.export_analysis_html(analysis)
    col_a.download_button(
        "JSON indir",
        data=json_path.read_text(encoding="utf-8"),
        file_name=json_path.name,
        mime="application/json",
    )
    col_b.download_button(
        "HTML indir",
        data=html_path.read_text(encoding="utf-8"),
        file_name=html_path.name,
        mime="text/html",
    )
    st.caption(f"Raporlar `{ctx.settings.report_dir}` dizinine yazıldı.")


# --------------------------------------------------------------------------- #
# Sayfa: Breach Intelligence
# --------------------------------------------------------------------------- #
def page_breach(ctx: AppContext) -> None:
    st.title("🧨 Breach Intelligence")
    st.caption(
        "Bu modül sızdırılmış veri indirmez ve çalıntı kimlik bilgilerini kullanmaz. "
        "Yalnızca yapılandırılmış istihbarat kayıtları, izinli sağlayıcı bildirimleri ve "
        "analistin kaydettiği iddialar işlenir."
    )

    tab_profiles, tab_findings, tab_manual = st.tabs(
        ["İzleme profilleri", "Sızıntı iddiaları", "Manuel iddia ekle"]
    )

    # ------------------------------------------------------------------ #
    with tab_profiles:
        st.subheader("Kurum profilleri")
        with st.form("org_form"):
            col1, col2 = st.columns([2, 3])
            org_name = col1.text_input("Kurum / proje adı")
            description = col2.text_input("Açıklama")
            create = st.form_submit_button("Profil oluştur")
        if create and org_name.strip():
            ctx.repos.organizations.create(org_name.strip(), description.strip())
            ctx.repos.audit.log(
                "organization_created", entity_type="organization", entity_id=org_name.strip()
            )
            st.success("Profil oluşturuldu.")
            st.rerun()

        organizations = ctx.repos.organizations.list()
        if not organizations:
            st.caption("Henüz kurum profili yok.")
        for org in organizations:
            with st.container(border=True):
                header = st.columns([3, 2, 1])
                header[0].markdown(f"**{org['name']}**")
                header[1].caption(org["description"] or "açıklama yok")
                if header[2].button("Sil", key=f"del_org_{org['id']}"):
                    ctx.repos.organizations.delete(org["id"])
                    st.rerun()

                st.caption(
                    "Bildirimler: "
                    + ("açık" if org["notifications_enabled"] else "kapalı")
                    + " · İzlenen varlıklar: "
                    + str(len(org.get("assets") or []))
                )

                if org.get("assets"):
                    st.dataframe(
                        [
                            {
                                "Tür": a["asset_type"],
                                "Değer": a["value"],
                                "Doğrulanmış": "evet" if a["verified"] else "hayır",
                            }
                            for a in org["assets"]
                        ],
                        use_container_width=True,
                        hide_index=True,
                    )

                with st.form(f"asset_form_{org['id']}"):
                    c1, c2, c3 = st.columns([2, 3, 1])
                    asset_type = c1.selectbox("Varlık türü", ASSET_TYPES, key=f"at_{org['id']}")
                    asset_value = c2.text_input("Değer (domain, marka, takma ad…)", key=f"av_{org['id']}")
                    verified = c3.checkbox("Doğrulanmış", value=asset_type in ("domain", "email_domain"))
                    if st.form_submit_button("Varlık ekle") and asset_value.strip():
                        ctx.repos.assets.add(
                            org["id"], asset_type, asset_value.strip().lower(), verified=verified
                        )
                        st.rerun()

        st.caption(
            "Not: Aynı adı taşıyan farklı kurumlarla yanlış eşleşmeyi azaltmak için yalnızca "
            "doğrulanmış domainler güçlü ilişkilendirme sayılır; marka/isim benzerliği zayıf sinyaldir."
        )

    # ------------------------------------------------------------------ #
    with tab_findings:
        findings = ctx.repos.findings.list(finding_type=FindingType.BREACH_CLAIM, limit=200)
        orgs = ctx.repos.organizations.list()
        col1, col2, col3 = st.columns(3)
        org_filter = col1.selectbox(
            "Kurum", ["tümü"] + [o["name"] for o in orgs], key="breach_org_filter"
        )
        status_filter = col2.selectbox(
            "Doğrulama durumu",
            ["tümü"] + [str(s) for s in VerificationStatus],
            key="breach_status_filter",
        )
        search = col3.text_input("Ara (domain, referans, özet)", key="breach_search")

        filtered = [
            f
            for f in findings
            if (org_filter == "tümü" or f.organization == org_filter)
            and (status_filter == "tümü" or str(f.verification_status) == status_filter)
            and (
                not search
                or search.lower()
                in " ".join(
                    filter(
                        None,
                        [f.matched_domain, f.source_reference, f.evidence_summary, f.organization],
                    )
                ).lower()
            )
        ]

        if filtered:
            st.dataframe(finding_rows(filtered), use_container_width=True, hide_index=True)
            selected_id = st.selectbox(
                "Ayrıntı için bulgu seçin", [f.finding_id for f in filtered], key="breach_detail_select"
            )
            selected = next((f for f in filtered if f.finding_id == selected_id), None)
            if selected:
                st.divider()
                render_finding_detail(ctx, selected, key_prefix="breach_")
        else:
            st.caption("Filtreye uyan sızıntı iddiası bulunamadı.")

    # ------------------------------------------------------------------ #
    with tab_manual:
        st.subheader("Manuel iddia kaydı")
        st.caption(
            "Analistin gözlemlediği bir kaydın güvenli referansı ve kısa özeti eklenir. "
            "Manuel kayıtlar tek başına doğrulanmış ihlal sayılmaz; durum 'doğrulanmamış iddia' olarak başlar."
        )
        orgs = ctx.repos.organizations.list()
        with st.form("manual_claim_form"):
            col1, col2 = st.columns(2)
            org_name = col1.selectbox(
                "İlgili kurum profili", ["(yok)"] + [o["name"] for o in orgs]
            )
            source_name = col2.text_input("Kaynak adı", value="manual")
            reference = col1.text_input("Kaynak referansı / URL")
            domain = col2.text_input("İlişkili domain (varsa)")
            claimed_date = col1.date_input("İddia edilen olay tarihi", value=None)
            data_types = col2.text_input(
                "İddia edilen veri türleri (virgülle)", placeholder="credentials, email"
            )
            summary = st.text_area("Kanıt özeti (hassas veri yazmayın)")
            submitted = st.form_submit_button("İddiayı kaydet", type="primary")

        if submitted:
            if not summary.strip():
                st.error("Kanıt özeti boş olamaz.")
                return
            organization, reasons = ctx.finder.match_organization(
                domain=domain.strip() or None,
                text=summary,
                explicit_name=None if org_name == "(yok)" else org_name,
            )
            finding = Finding(
                finding_id="",
                finding_type=FindingType.BREACH_CLAIM,
                organization_id=organization["id"] if organization else None,
                organization=organization["name"] if organization else (org_name if org_name != "(yok)" else None),
                matched_domain=domain.strip().lower() or None,
                source_type=SourceType.BREACH_FEED,
                source_name=source_name.strip() or "manual",
                source_reference=reference.strip() or None,
                claimed_event_date=(
                    datetime.combine(claimed_date, datetime.min.time()).astimezone()
                    if isinstance(claimed_date, date)
                    else None
                ),
                claimed_data_types=[
                    part.strip().lower().replace(" ", "_")
                    for part in data_types.split(",")
                    if part.strip()
                ],
                verification_status=VerificationStatus.UNVERIFIED_CLAIM,
                evidence_summary=summary.strip(),
                metadata={
                    "origin": "manual",
                    "analyst_reported": True,
                    "association_reasons": reasons,
                },
            )
            outcome = ctx.finder.save(
                finding,
                evidence=Evidence(
                    source_name=finding.source_name,
                    source_type=finding.source_type,
                    source_reference=finding.source_reference,
                    summary=summary.strip()[:600],
                ),
                actor="analyst",
            )
            st.success(
                f"Kayıt oluşturuldu: {outcome.finding.finding_id} "
                f"(risk: {outcome.finding.risk_level}, doğrulama: {outcome.finding.verification_status})"
            )
            if reasons:
                st.info("İlişkilendirme gerekçeleri: " + "; ".join(reasons))


# --------------------------------------------------------------------------- #
# Sayfa: Dark Web & Kaynaklar
# --------------------------------------------------------------------------- #
def page_sources(ctx: AppContext) -> None:
    st.title("🌐 Dark Web Monitoring & Kaynaklar")
    st.caption(
        "Yalnızca erişilebilir ve kullanımına izin verilen yapılandırılmış kaynaklar izlenir. "
        "Bu modül tüm Tor ağını taradığını iddia etmez; kapsam, kontrol edilen kaynaklarla sınırlıdır."
    )

    st.subheader("Kaynak yönetimi")
    configs = ctx.repos.sources.list()
    health_map = {h.source_name: h for h in ctx.repos.sources.health_all()}

    for config in configs:
        health = health_map.get(config.name)
        with st.container(border=True):
            head = st.columns([3, 2, 2, 2])
            head[0].markdown(f"**{config.name}** · `{config.adapter}`")
            head[1].caption(f"{config.source_type} / {config.category}")
            head[2].caption(
                "Durum: "
                + (str(health.status) if health else "bilinmiyor")
                + (f" · ardışık hata: {health.consecutive_failures}" if health and health.consecutive_failures else "")
            )
            head[3].caption(f"Sıklık: {config.check_interval_minutes} dk")

            col_a, col_b = st.columns([1, 1])
            enabled = col_a.toggle("Etkin", value=config.enabled, key=f"en_{config.name}")
            category1 = config.category == "structured_api"
            capabilities = []
            adapter = ctx.monitor.adapters.get(config.name)
            if adapter:
                capabilities = sorted(adapter.capabilities)
            col_b.caption("Yetenekler: " + (", ".join(capabilities) or "-"))

            if enabled != config.enabled:
                update_source_settings(ctx.repos, config.name, {"enabled": enabled})
                ctx.refresh_adapters()
                st.rerun()

            if config.notes:
                st.caption(config.notes)

            settings_editable = {k: v for k, v in config.settings.items() if k != "api_key_env"}
            with st.expander("Kaynak ayarları"):
                st.caption(
                    "Kimlik bilgileri veritabanında tutulmaz; yalnızca `.env` dosyasındaki ortam "
                    "değişkeninden okunur."
                )
                st.json(settings_editable, expanded=False)
                with st.form(f"settings_{config.name}"):
                    new_url = st.text_input(
                        "Kaynak URL", value=str(config.settings.get("url") or ""), key=f"url_{config.name}"
                    )
                    interval = st.number_input(
                        "Kontrol sıklığı (dakika)",
                        min_value=5,
                        max_value=10080,
                        value=int(config.check_interval_minutes),
                        step=5,
                        key=f"int_{config.name}",
                    )
                    updates: dict[str, Any] = {"url": new_url.strip() or None}
                    if config.adapter == "darkweb_source":
                        updates["confirmed_authorized"] = st.checkbox(
                            "Kaynağın kullanımına izin verildiğini beyan ediyorum",
                            value=bool(config.settings.get("confirmed_authorized")),
                            key=f"auth_{config.name}",
                        )
                        updates["terms_reviewed"] = st.checkbox(
                            "Kullanım koşullarını inceledim",
                            value=bool(config.settings.get("terms_reviewed")),
                            key=f"terms_{config.name}",
                        )
                    if st.form_submit_button("Ayarları kaydet"):
                        ctx.repos.sources.upsert(
                            config.model_copy(
                                update={
                                    "settings": {**config.settings, **updates},
                                    "check_interval_minutes": int(interval),
                                }
                            )
                        )
                        ctx.repos.audit.log(
                            "source_settings_updated", entity_type="source", entity_id=config.name
                        )
                        ctx.refresh_adapters()
                        st.success("Ayarlar kaydedildi.")
                        st.rerun()

            actions = st.columns([1, 1, 3])
            if actions[0].button("Kontrol et", key=f"run_{config.name}"):
                adapter = ctx.monitor.adapters.get(config.name)
                if adapter is None:
                    st.error("Adaptör bulunamadı.")
                elif not adapter.supports("fetch_updates"):
                    st.warning("Bu kaynak periyodik kayıt çekmeyi desteklemiyor (yalnızca IOC sorgusu).")
                elif not adapter.enabled:
                    st.warning("Kaynak etkin değil. Önce 'Etkin' anahtarını açın.")
                else:
                    with st.spinner(f"{config.name} kontrol ediliyor…"):
                        result = ctx.monitor.run_source(config.name, triggered_by="ui")
                    if result.error:
                        st.error(f"{config.name}: {result.error}")
                    else:
                        st.success(result.summary_text)
                        totals = result.changes.totals
                        st.caption(
                            f"Yeni: {totals['new']} · Güncellenen: {totals['updated']} · "
                            f"Değişmeyen: {totals['unchanged']} · Kayıp: {totals['missing']}"
                        )
                    st.rerun()

            if actions[1].button("Bağlantıyı test et", key=f"test_{config.name}"):
                adapter = ctx.monitor.adapters.get(config.name)
                if adapter is None:
                    st.error("Adaptör bulunamadı.")
                else:
                    with st.spinner("Test ediliyor…"):
                        ok = adapter.check_connection()
                    st.success("Bağlantı başarılı.") if ok else st.error("Bağlantı kurulamadı.")

    st.divider()
    st.subheader("Kontrol geçmişi")
    runs = ctx.repos.source_runs.list_recent(limit=40)
    if runs:
        st.dataframe(
            [
                {
                    "Kaynak": r.source_name,
                    "Tetikleyen": r.triggered_by,
                    "Başlangıç": fmt(r.started_at),
                    "Bitiş": fmt(r.finished_at),
                    "Durum": str(r.status),
                    "Kayıt": r.records_fetched,
                    "Yeni": r.findings_created,
                    "Güncelleme": r.findings_updated,
                    "Hata": r.error_message or "-",
                }
                for r in runs
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.caption("Kayıt yok.")

    st.divider()
    st.subheader("Zamanlanmış görevler")
    st.caption(
        "Zamanlayıcı varsayılan olarak kapalıdır (`SCHEDULER_ENABLED`). "
        "Etkin kaynaklar için planlanan görevler aşağıda listelenir."
    )
    jobs = ctx.scheduler.jobs()
    if jobs:
        st.dataframe(
            [
                {
                    "Kaynak": job.get("source_name"),
                    "Sıklık (dk)": job.get("minutes"),
                    "Sonraki çalışma": fmt(job.get("next_run_time")) if job.get("next_run_time") else "-",
                    "Zamanlayıcı": "aktif" if job.get("scheduled") else "kapalı",
                }
                for job in jobs
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.caption("Etkin kaynak yok.")

    if ctx.scheduler.is_running():
        if st.button("Zamanlayıcıyı durdur"):
            ctx.scheduler.shutdown()
            st.rerun()
    else:
        if st.button("Zamanlayıcıyı başlat"):
            ctx.scheduler.start()
            st.rerun()


# --------------------------------------------------------------------------- #
# Sayfa: Dark Web Kaynak Kataloğu 
# --------------------------------------------------------------------------- #
def catalog_rows(entries: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "Kategori": e.category_label or e.category,
            "Ad": e.name,
            "Ağ": NETWORK_LABELS.get(str(e.network), str(e.network)),
            "Durum": CATALOG_STATUS_LABELS.get(str(e.status), str(e.status)),
            "Adres": e.url or "-",
            "İzleniyor": "evet" if e.tracked else "",
            "Açıklama": e.description,
        }
        for e in entries
    ]


def page_catalog(ctx: AppContext) -> None:
    st.title("🌑 Dark Web Kaynak Kataloğu ")
    st.caption(
        "Bu modül bir **kaynak kataloğudur**, tarama motoru değildir.  "
        "kategoriler (fidye çetesi sızıntı siteleri, forumlar, pazarlar, Telegram/Discord kanalları...) "
        "OpenTIP panosuna aktarılır. Katalog kayıtları bulgu üretmez ve doğrulama/risk akışına girmez; "
        "hiçbir onion adresine bağlanılmaz, yalnızca herkese açık liste metni okunur."
    )

    category_keys = [c.key for c in DEEPDARK_CATEGORIES]
    category_labels = {c.key: c.label for c in DEEPDARK_CATEGORIES}

    # --- Eşitleme -------------------------------------------------------- #
    st.subheader("Katalog eşitleme")
    st.caption(
        "Kategoriler herkese açık GitHub içeriğinden okunur. Bir kategori hata verse bile "
        "diğerleri eşitlenir ve hata ayrıca kaydedilir."
    )
    selected = st.multiselect(
        "Kategoriler",
        category_keys,
        default=category_keys,
        format_func=lambda key: category_labels.get(key, key),
    )
    col_sync, col_test = st.columns([1, 1])
    if col_sync.button("Seçili kategorileri eşitle", type="primary", disabled=not selected):
        with st.spinner("Katalog eşitleniyor…"):
            results = ctx.catalog.sync(selected)
        succeeded = [r for r in results if r.status == "ok"]
        failed = [r for r in results if r.status != "ok"]
        if succeeded:
            st.success(
                f"{len(succeeded)} kategori eşitlendi · toplam "
                f"{sum(r.entries_fetched for r in succeeded)} kayıt okundu."
            )
        for outcome in failed:
            st.error(f"{outcome.category_label or outcome.category}: {outcome.error_message}")
    if col_test.button("Katalog deposuna bağlantıyı test et"):
        with st.spinner("Test ediliyor…"):
            reachable = ctx.catalog.check_connection()
        if reachable:
            st.success("Katalog deposuna erişim başarılı.")
        else:
            st.error("Katalog deposuna erişilemedi. Adresi ve ağ erişimini kontrol edin.")

    # --- Özet ------------------------------------------------------------- #
    stats = ctx.catalog.stats()
    st.divider()
    metrics = st.columns(5)
    metrics[0].metric("Katalog kaydı", stats["total"])
    metrics[1].metric("İzlemeye alınan", stats["tracked"])
    metrics[2].metric("Tor (onion)", stats["by_network"].get("tor", 0))
    metrics[3].metric("Clearnet", stats["by_network"].get("clearnet", 0))
    metrics[4].metric(
        "Son başarılı eşitleme",
        fmt(stats["last_success_at"]) if stats["last_success_at"] else "-",
    )
    if stats["total"] == 0:
        st.info("Katalog boş. Yukarıdan bir eşitleme çalıştırın.")
        return

    # --- Filtreler -------------------------------------------------------- #
    st.divider()
    st.subheader("Katalog kayıtları")
    filters = st.columns([2, 2, 2, 2, 2])
    category_filter = filters[0].selectbox(
        "Kategori",
        ["tümü"] + category_keys,
        format_func=lambda key: "tümü" if key == "tümü" else category_labels.get(key, key),
    )
    network_filter = filters[1].selectbox(
        "Ağ",
        ["tümü"] + [str(n) for n in CatalogNetwork],
        format_func=lambda value: "tümü" if value == "tümü" else NETWORK_LABELS.get(value, value),
    )
    status_filter = filters[2].selectbox(
        "Durum",
        ["tümü"] + [str(s) for s in CatalogStatus],
        format_func=lambda value: (
            "tümü" if value == "tümü" else CATALOG_STATUS_LABELS.get(value, value)
        ),
    )
    tracked_only = filters[3].checkbox("Yalnızca izlenenler")
    query = filters[4].text_input("Ara (ad, adres, açıklama)")

    entries = ctx.catalog.search(
        query=query.strip() or None,
        category=None if category_filter == "tümü" else category_filter,
        network=None if network_filter == "tümü" else CatalogNetwork(network_filter),
        status=None if status_filter == "tümü" else CatalogStatus(status_filter),
        tracked_only=tracked_only,
        limit=1000,
    )
    st.caption(f"{len(entries)} kayıt listeleniyor (katalog toplamı: {stats['total']}).")

    if entries:
        st.dataframe(catalog_rows(entries), use_container_width=True, hide_index=True)
    else:
        st.caption("Filtrelerle eşleşen kayıt yok.")

    if not entries:
        return

    # --- Ayrıntı ve izlemeye alma ----------------------------------------- #
    st.divider()
    st.subheader("Kayıt ayrıntısı")
    selected_id = st.selectbox(
        "Kayıt seçin",
        [e.entry_id for e in entries],
        format_func=lambda entry_id: next(
            (f"{e.name} · {e.category_label or e.category}" for e in entries if e.entry_id == entry_id),
            str(entry_id),
        ),
        key="catalog_entry_select",
    )
    entry = next((e for e in entries if e.entry_id == selected_id), None)
    if entry is not None:
        st.markdown(f"**{entry.name}** · {entry.category_label or entry.category}")
        st.caption(
            f"Ağ: {NETWORK_LABELS.get(str(entry.network), str(entry.network))} · "
            f"Durum: {CATALOG_STATUS_LABELS.get(str(entry.status), str(entry.status))} · "
            f"Son eşitleme: {fmt(entry.last_synced_at)}"
        )
        if entry.url:
            st.caption("Adres (kopyalamak için seçin):")
            st.code(entry.url, language=None)
        if entry.description:
            st.write(entry.description)
        if entry.columns:
            st.json(entry.columns, expanded=False)

        if entry.tracked:
            st.success(
                "Bu kayıt izlemeye alınmış. İlgili kaynak: "
                f"`{entry.source_name}` — 'Dark Web Monitoring' sayfasından yönetilir."
            )
        elif not entry.url:
            st.warning("Bu kaydın izlenecek bir adresi yok.")
        else:
            st.caption(
                "İzlemeye alındığında kaynak **kapalı** ve **izin beyanı yapılmamış** olarak "
                "oluşturulur. Kaynağın kullanım koşulları onaylanmadan hiçbir istek yapılmaz."
            )
            if st.button("İzlemeye al (darkweb_source kaynağı oluştur)"):
                try:
                    config = ctx.catalog.promote(entry)
                except ValueError as exc:
                    st.error(str(exc))
                else:
                    ctx.refresh_adapters()
                    st.success(f"Kaynak oluşturuldu: `{config.name}` (kapalı, izin bekliyor).")

    # --- Müşteri / varlık eşleştirme -------------------------------------- #
    st.divider()
    with st.expander("İzlenen varlıklarla eşleştir (müşteri takibi)"):
        st.caption(
            "Kurum profillerinde tanımlı varlıklar (alan adı, marka, takma ad) katalogda aranır. "
            "Eşleşme tek başına ihlal kanıtı değildir; yalnızca incelenecek kaynak işaretidir."
        )
        default_terms = ", ".join(ctx.catalog.monitored_terms())
        raw_terms = st.text_area(
            "Aranacak terimler (virgül veya satır ile ayırın)",
            value=default_terms,
            height=80,
            key="catalog_match_terms",
        )
        terms = [
            term.strip()
            for chunk in raw_terms.splitlines()
            for term in chunk.split(",")
            if term.strip()
        ]
        if st.button("Katalogda ara", disabled=not terms):
            matches = ctx.catalog.match_terms(terms)
            if not matches:
                st.info("Eşleşme bulunamadı. Terimleri kısaltmayı deneyin (ör. alan adı yerine marka adı).")
            else:
                st.caption(f"{len(matches)} eşleşme bulundu.")
                st.dataframe(
                    [
                        {
                            "Aranan terim": term,
                            "Kategori": matched.category_label or matched.category,
                            "Kayıt": matched.name,
                            "Adres": matched.url or "-",
                            "Durum": CATALOG_STATUS_LABELS.get(str(matched.status), str(matched.status)),
                        }
                        for term, matched in matches
                    ],
                    use_container_width=True,
                    hide_index=True,
                )

    # --- Eşitleme geçmişi -------------------------------------------------- #
    syncs = ctx.repos.catalog_syncs.list_recent(limit=40)
    with st.expander("Son eşitleme kayıtları"):
        if syncs:
            st.dataframe(
                [
                    {
                        "Kategori": row.category_label or row.category,
                        "Durum": row.status,
                        "Başlangıç": fmt(row.started_at),
                        "Okunan": row.entries_fetched,
                        "Yeni": row.entries_created,
                        "Güncellenen": row.entries_updated,
                        "Kaldırılan": row.entries_missing,
                        "Hata": row.error_message or "-",
                    }
                    for row in syncs
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption("Henüz eşitleme kaydı yok.")


# --------------------------------------------------------------------------- #
# Sayfa: Findings & Reports
# --------------------------------------------------------------------------- #
def page_findings(ctx: AppContext) -> None:
    st.title("📁 Findings & Reports")

    col1, col2, col3, col4 = st.columns(4)
    type_filter = col1.selectbox(
        "Bulgu türü",
        ["tümü"] + [str(t) for t in FindingType],
        format_func=lambda v: "tümü" if v == "tümü" else TYPE_LABELS.get(v, v),
    )
    status_filter = col2.selectbox(
        "Doğrulama durumu",
        ["tümü"] + [str(s) for s in VerificationStatus],
        format_func=lambda v: "tümü" if v == "tümü" else STATUS_LABELS.get(v, v),
    )
    risk_filter = col3.selectbox("Risk", ["tümü"] + RISK_ORDER)
    search = col4.text_input("Ara")

    findings = ctx.finder.list(
        finding_type=None if type_filter == "tümü" else FindingType(type_filter),
        verification_status=None if status_filter == "tümü" else VerificationStatus(status_filter),
        risk_level=None if risk_filter == "tümü" else RiskLevel(risk_filter),
        search=search or None,
        limit=500,
    )

    st.caption(f"{len(findings)} bulgu listeleniyor.")
    if findings:
        st.dataframe(finding_rows(findings), use_container_width=True, hide_index=True)
        selected_id = st.selectbox(
            "Ayrıntı için bulgu seçin", [f.finding_id for f in findings], key="all_detail_select"
        )
        selected = next((f for f in findings if f.finding_id == selected_id), None)
        if selected:
            st.divider()
            render_finding_detail(ctx, selected, key_prefix="all_")
    else:
        st.caption("Bulgu bulunamadı.")

    st.divider()
    st.subheader("Raporlar")
    st.caption(
        "Raporlar API anahtarı veya hassas yapılandırma içermez. Sızdırılmış veri gövdeleri "
        "saklanmadığı için raporlara da yazılmaz."
    )
    export_scope = st.radio(
        "Kapsam", ["Filtrelenmiş liste", "Tüm bulgular"], horizontal=True, key="report_scope"
    )
    export_targets = findings if export_scope == "Filtrelenmiş liste" else ctx.finder.list(limit=1000)

    col_json, col_html = st.columns(2)
    json_path = ctx.exporter.export_findings_json(export_targets)
    html_path = ctx.exporter.export_findings_html(
        export_targets,
        notice=(
            "Sızıntı iddiaları tek başına doğrulanmış ihlal olarak değerlendirilmez. "
            "Her bulgunun kaynağı, doğrulama durumu ve risk gerekçesi ayrıca belirtilmiştir."
        ),
    )
    col_json.download_button(
        f"JSON indir ({len(export_targets)} bulgu)",
        data=json_path.read_text(encoding="utf-8"),
        file_name=json_path.name,
        mime="application/json",
    )
    col_html.download_button(
        f"HTML indir ({len(export_targets)} bulgu)",
        data=html_path.read_text(encoding="utf-8"),
        file_name=html_path.name,
        mime="text/html",
    )
    st.caption(f"Çıktı dizini: `{ctx.settings.report_dir}`")

    with st.expander("Son denetim kayıtları"):
        st.dataframe(
            [
                {
                    "Zaman": fmt(row["created_at"]),
                    "İşlem": row["action"],
                    "Varlık": row["entity_type"],
                    "ID": row["entity_id"],
                    "Ayrıntı": json.dumps(row["detail"], ensure_ascii=False)[:160],
                }
                for row in ctx.repos.audit.list(limit=50)
            ],
            use_container_width=True,
            hide_index=True,
        )


# --------------------------------------------------------------------------- #
# Kenar çubuğu
# --------------------------------------------------------------------------- #
def sidebar(ctx: AppContext) -> str:
    st.sidebar.title("🛡️ OpenTIP")
    st.sidebar.caption("Open Threat Intelligence Platform · MVP")
    page = st.sidebar.radio(
        "Modüller",
        [
            "Dashboard",
            "IOC Analysis",
            "Breach Intelligence",
            "Dark Web Monitoring",
            "Dark Web Kataloğu",
            "Findings & Reports",
        ],
        label_visibility="collapsed",
    )
    st.sidebar.divider()
    st.sidebar.metric("Açık alarm", ctx.notifier.open_count())
    stats = ctx.repos.findings.stats()
    st.sidebar.metric("Toplam bulgu", stats["total"])
    st.sidebar.metric("Toplam IOC kaydı", ctx.repos.iocs.count())

    st.sidebar.divider()
    st.sidebar.caption(
        "Kapsam notu: Yalnızca yapılandırılmış ve erişim izni bulunan kaynaklar kontrol edilir. "
        "Kaynak hatası, eşleşme yokluğundan ayrı değerlendirilir."
    )
    return page


def main() -> None:
    ctx = bootstrap()
    page = sidebar(ctx)
    if page == "Dashboard":
        page_dashboard(ctx)
    elif page == "IOC Analysis":
        page_ioc(ctx)
    elif page == "Breach Intelligence":
        page_breach(ctx)
    elif page == "Dark Web Monitoring":
        page_sources(ctx)
    elif page == "Dark Web Kataloğu":
        page_catalog(ctx)
    else:
        page_findings(ctx)


if __name__ == "__main__":
    main()
