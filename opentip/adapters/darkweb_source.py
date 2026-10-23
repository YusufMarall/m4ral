"""İzinli Dark Web / tehdit istihbaratı kaynağı adaptörü (PRD 9.2, 9.6).

Bu adaptör **Kategori 2 — izinli web kaynakları** için tasarlanmıştır.
Davranış kuralları:

* Yalnızca yapılandırmada belirtilen tek URL'ye istek yapılır.
* Bilinmeyen bağlantılar takip edilmez; sayfa içindeki linkler açılmaz.
* İndirilen dosya veya içerik otomatik çalıştırılmaz.
* Dış kaynak metni "talimat" değil, analiz edilecek **güvenilmeyen veri** kabul edilir.
* Modül, tüm Tor ağını taradığını iddia etmez; yalnızca gerçekten kontrol
  edilen kapsamı raporlar.

Kaynak kullanımına izin verildiğinin operatör tarafından açıkça beyan edilmesi
zorunludur (`confirmed_authorized: true`).
"""

from __future__ import annotations

from typing import Any, Optional

from models import (
    Finding,
    FindingType,
    SourceCategory,
    SourceType,
    VerificationStatus,
    utcnow,
)
from core.normalizer import (
    content_digest,
    parse_timestamp,
    records_from_text,
    sanitize_text,
)

from .base import (
    CAP_CONNECTION_CHECK,
    CAP_FETCH_UPDATES,
    AdapterConfigError,
    BaseAdapter,
)


class DarkWebSourceAdapter(BaseAdapter):
    adapter_name = "darkweb_source"
    source_type = SourceType.DARKWEB_SOURCE
    default_category = SourceCategory.AUTHORIZED_WEB
    capabilities = {CAP_FETCH_UPDATES, CAP_CONNECTION_CHECK}
    required_settings = ("url",)

    # ------------------------------------------------------------------ #
    @property
    def source_url(self) -> str:
        return self.require_config("url")

    def _assert_authorized(self) -> None:
        """Kaynağın izinli olduğu açıkça beyan edilmediyse çalışmayı reddeder."""
        if not self.setting("confirmed_authorized", False):
            raise AdapterConfigError(
                f"{self.name}: kaynak kullanım izni beyan edilmedi. "
                "Kaynak ayarlarında 'confirmed_authorized' değerini true yapmadan "
                "bu adaptör çalıştırılmaz (PRD 9.6)."
            )
        if not self.setting("terms_reviewed", False):
            raise AdapterConfigError(
                f"{self.name}: kaynağın kullanım koşulları incelendi olarak "
                "işaretlenmedi. 'terms_reviewed' ayarını doğruladıktan sonra etkinleştirin."
            )

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json, text/plain;q=0.9, text/html;q=0.5"}
        key = self.secret()
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    def check_connection(self) -> bool:
        try:
            self._assert_authorized()
            response = self.request(
                "GET", self.source_url, headers=self._headers(), retries=1, allow_redirects=False
            )
            ok = getattr(response, "status_code", 0) == 200
            self.record_run(success=ok, message="" if ok else "Kaynak erişimi doğrulanamadı")
            return ok
        except Exception as exc:
            self.record_run(success=False, message=str(exc))
            return False

    def fetch_updates(self, since: Optional[str] = None, **kwargs: Any) -> list[Any]:
        """Yapılandırılmış kaynaktan yeni kayıtları alır.

        Yönlendirmeler otomatik takip edilmez; yanıt gövdesi hiçbir zaman
        çalıştırılmaz (PRD 9.6).
        """
        self._assert_authorized()
        params: dict[str, Any] = {}
        if since:
            params["since"] = since

        response = self.request(
            "GET",
            self.source_url,
            params=params or None,
            headers=self._headers(),
            allow_redirects=False,
        )

        content_type = str(getattr(response, "headers", {}).get("Content-Type", "")).lower()
        records: list[Any]
        if "json" in content_type:
            payload = self.json_body(response)
            if isinstance(payload, list):
                records = payload
            elif isinstance(payload, dict):
                records = payload.get("records") or payload.get("items") or payload.get("data") or []
            else:
                records = []
            records = [r for r in records if isinstance(r, dict)]
        else:
            # Düz metin / HTML: yalnızca metin olarak alınır, hiçbir şey yürütülmez.
            text = getattr(response, "text", "") or ""
            records = [{"text": text}] if text.strip() else []

        self.record_run(success=True, message=f"{len(records)} kayıt")
        return records

    def normalize_record(self, raw: Any) -> Finding:
        """Kaynak kaydını ortak bulgu modeline dönüştürür."""
        record = raw or {}
        text_source = (
            record.get("summary")
            or record.get("description")
            or record.get("title")
            or record.get("text")
            or ""
        )
        summary = sanitize_text(text_source, max_length=600)
        indicators = records_from_text(
            text_source, source_name=self.name, source_type=self.source_type
        )
        reference = record.get("reference") or record.get("url") or f"{self.name}:{self.source_url}"

        return Finding(
            finding_id="",
            finding_type=FindingType.DARKWEB_RECORD,
            organization=record.get("organization") or record.get("target"),
            matched_domain=(str(record["domain"]).lower() if record.get("domain") else None),
            source_type=self.source_type,
            source_name=self.name,
            source_reference=reference,
            first_seen=parse_timestamp(record.get("first_seen") or record.get("date")) or utcnow(),
            last_checked=utcnow(),
            claimed_event_date=parse_timestamp(record.get("claimed_date")),
            claimed_data_types=[
                str(t).strip().lower().replace(" ", "_")
                for t in (record.get("data_types") or [])
                if str(t).strip()
            ],
            # İçerik tek başına doğrulama sağlamaz (PRD 8.5, 9.1).
            verification_status=VerificationStatus.UNVERIFIED_CLAIM,
            evidence_summary=summary or "İzlenen kaynaktan alınan kayıt (içerik özeti boş).",
            source_reliability=self.source_config.reliability,
            metadata={
                "content_digest": content_digest(text_source),
                "indicators": [value for value, _ in indicators],
                "source_url": self.source_url,
                "coverage_note": (
                    "Bu kayıt yalnızca yapılandırılmış tek bir kaynakta yapılan kontrolün "
                    "sonucudur; Dark Web'in tamamının tarandığı iddia edilmez."
                ),
                "untrusted_source": True,
            },
        )
