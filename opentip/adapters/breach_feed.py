"""İzinli breach intelligence akışı adaptörü (PRD 8.7).

Yapılandırılmış bir sağlayıcı API'si üzerinden sızıntı iddialarını alır.
Bu adaptör **sızdırılmış veri indirmez ve çalıntı kimlik bilgilerini kullanmaz**
(PRD 4.3, 8.1). Yalnızca sağlayıcının bildirdiği metadata ve kanıt referansı
saklanır.

Beklenen yanıt biçimi (esnek): bir JSON listesi ya da aşağıdaki gibi bir nesne::

    {"records": [{"id": "...", "organization": "...", "domain": "...",
                  "summary": "...", "data_types": ["credentials"],
                  "claimed_date": "2026-01-01",
                  "reference": "https://provider/record/1",
                  "confidence": 0.7, "verified": false}]}
"""

from __future__ import annotations

from typing import Any, Optional

from models import (
    Finding,
    FindingType,
    IOCInput,
    IOCRecord,
    SourceCategory,
    SourceType,
    VerificationStatus,
    utcnow,
)
from core.normalizer import (
    build_ioc_record,
    content_digest,
    parse_timestamp,
    records_from_text,
    sanitize_text,
)

from .base import (
    CAP_CONNECTION_CHECK,
    CAP_FETCH_UPDATES,
    CAP_IOC_LOOKUP,
    AdapterConfigError,
    BaseAdapter,
)

#: Sağlayıcının bildirdiği veri türlerinin ortak sözlüğe eşlenmesi.
_DATA_TYPE_ALIASES = {
    "email": "contact",
    "emails": "contact",
    "passwords": "credentials",
    "password": "credentials",
    "hashes": "credentials",
    "ssn": "personal_data",
    "pii": "personal_data",
    "customers": "customer_data",
    "customer": "customer_data",
    "cards": "credit_card",
    "cc": "credit_card",
    "db": "database",
}


class BreachFeedAdapter(BaseAdapter):
    adapter_name = "breach_feed"
    source_type = SourceType.BREACH_FEED
    default_category = SourceCategory.STRUCTURED_API
    capabilities = {CAP_FETCH_UPDATES, CAP_CONNECTION_CHECK, CAP_IOC_LOOKUP}
    required_settings = ("url",)

    # ------------------------------------------------------------------ #
    @property
    def feed_url(self) -> str:
        return self.require_config("url")

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        key = self.secret()
        if key:
            # Sağlayıcıya göre Bearer veya X-API-Key; arayüzde ayarlanabilir.
            scheme = str(self.setting("auth_scheme", "bearer")).lower()
            if scheme == "x-api-key":
                headers["X-API-Key"] = key
            else:
                headers["Authorization"] = f"Bearer {key}"
        return headers

    def check_connection(self) -> bool:
        try:
            response = self.request(
                "GET", self.feed_url, params={"limit": 1}, headers=self._headers(), retries=1
            )
            ok = getattr(response, "status_code", 0) == 200
            self.record_run(success=ok, message="" if ok else "Sağlayıcı erişimi doğrulanamadı")
            return ok
        except Exception as exc:
            self.record_run(success=False, message=str(exc))
            return False

    def fetch_updates(self, since: Optional[str] = None, limit: int = 200, **kwargs: Any) -> list[Any]:
        """Sağlayıcıdan yeni/değişen iddia kayıtlarını alır."""
        params: dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        if kwargs.get("query"):
            params["q"] = kwargs["query"]

        response = self.request("GET", self.feed_url, params=params, headers=self._headers())
        data = self.json_body(response)

        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            records = data.get("records") or data.get("data") or data.get("items") or []
        else:
            records = []

        self.record_run(success=True, message=f"{len(records)} kayıt")
        return [r for r in records if isinstance(r, dict)]

    def normalize_record(self, raw: Any) -> Finding:
        """Sağlayıcı kaydını ortak bulgu modeline dönüştürür."""
        record = raw or {}
        reference = (
            record.get("reference")
            or record.get("url")
            or (f"{self.name}:{record.get('id')}" if record.get("id") else None)
        )
        organization = (
            record.get("organization") or record.get("target") or record.get("company")
        )
        domain = record.get("domain") or record.get("matched_domain")
        summary_source = (
            record.get("summary")
            or record.get("description")
            or record.get("title")
            or record.get("text")
            or ""
        )
        data_types = self._normalize_data_types(
            record.get("data_types") or record.get("categories") or record.get("data")
        )

        # Sağlayıcı "doğrulandı" demediyse iddia doğrulanmamış kabul edilir.
        provider_verified = bool(record.get("verified") or record.get("confirmed"))
        status = (
            VerificationStatus.CORROBORATED if provider_verified else VerificationStatus.UNVERIFIED_CLAIM
        )

        try:
            confidence = float(record.get("confidence"))
            confidence = max(0.0, min(1.0, confidence))
        except (TypeError, ValueError):
            confidence = None

        indicators = records_from_text(
            summary_source, source_name=self.name, source_type=self.source_type
        )

        summary = sanitize_text(summary_source, max_length=600)
        return Finding(
            finding_id="",
            finding_type=FindingType.BREACH_CLAIM,
            organization=organization,
            matched_domain=str(domain).lower() if domain else None,
            source_type=self.source_type,
            source_name=self.name,
            source_reference=reference,
            first_seen=parse_timestamp(record.get("first_seen") or record.get("discovered_at")) or utcnow(),
            last_checked=utcnow(),
            claimed_event_date=parse_timestamp(
                record.get("claimed_date") or record.get("breach_date") or record.get("date")
            ),
            claimed_data_types=data_types,
            verification_status=status,
            evidence_summary=summary or "Sağlayıcı kaydı; özet bilgisi bulunmuyor.",
            source_reliability=(
                confidence if confidence is not None else self.source_config.reliability
            ),
            metadata={
                "provider_record_id": record.get("id"),
                "provider_verified": provider_verified,
                "data_size": record.get("records_count") or record.get("size"),
                "content_digest": content_digest(summary_source),
                "indicators": [record.value for record in indicators],
                # İçerik güvenilmeyen veridir; asla otomatik açılmaz (PRD 9.6).
                "untrusted_source": True,
            },
        )

    def lookup_ioc(self, ioc: IOCInput) -> list[IOCRecord]:
        """Sağlayıcı kayıtlarında göstergeyi arar."""
        matches = self.fetch_updates(query=ioc.value, limit=50)
        records: list[IOCRecord] = []
        for match in matches:
            records.append(
                build_ioc_record(
                    value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    source_name=self.name,
                    source_type=self.source_type,
                    source_reference=(
                        match.get("reference") or match.get("url") or f"{self.name}:{match.get('id')}"
                    ),
                    last_seen=parse_timestamp(match.get("date")),
                    tags=["breach-intelligence"],
                    risk_level=None,
                    confidence=0.5,
                    detail={"summary": sanitize_text(match.get("summary") or match.get("title"), 300)},
                )
            )
        return records

    # ------------------------------------------------------------------ #
    def _normalize_data_types(self, values: Any) -> list[str]:
        if values is None:
            return []
        if isinstance(values, str):
            values = [v.strip() for v in values.replace(";", ",").split(",")]
        result: list[str] = []
        for value in values:
            key = str(value).strip().lower().replace(" ", "_")
            if not key:
                continue
            mapped = _DATA_TYPE_ALIASES.get(key, key)
            if mapped not in result:
                result.append(mapped)
        return result
