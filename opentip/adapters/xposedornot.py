"""XposedOrNot adaptörü.

Geçici ve düşük bütçeli kullanım için iki modu destekler:

* Genel/public breach sorgusu: `GET /v1/breaches?domain=...`
* Doğrulanmış domain izleme: `POST /v1/domain-breaches` (`XPOSEDORNOT_API_KEY`)

Public sorgu API anahtarı gerektirmez. Domain-breaches uç noktası ise yalnızca
alan adı doğrulaması yapılmış hesaplar için kullanılabilir.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlsplit

from models import (
    Finding,
    FindingType,
    IOCInput,
    IOCRecord,
    IOCType,
    SourceCategory,
    SourceType,
    VerificationStatus,
    utcnow,
)
from core.normalizer import (
    build_ioc_record,
    content_digest,
    parse_timestamp,
    sanitize_text,
)

from .base import (
    CAP_CONNECTION_CHECK,
    CAP_FETCH_UPDATES,
    CAP_IOC_LOOKUP,
    AdapterConfigError,
    BaseAdapter,
)

XON_BASE_URL = "https://api.xposedornot.com"


class XposedOrNotAdapter(BaseAdapter):
    adapter_name = "xposedornot"
    source_type = SourceType.BREACH_FEED
    default_category = SourceCategory.STRUCTURED_API
    capabilities = {CAP_IOC_LOOKUP, CAP_CONNECTION_CHECK, CAP_FETCH_UPDATES}

    @property
    def base_url(self) -> str:
        return str(self.setting("url", XON_BASE_URL)).rstrip("/")

    def _headers(self, *, require_key: bool = False) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        key = self.secret()
        if key:
            headers["x-api-key"] = key
        elif require_key:
            raise AdapterConfigError(
                "XposedOrNot domain monitoring için API anahtarı gerekli. "
                ".env dosyasında XPOSEDORNOT_API_KEY tanımlayın."
            )
        return headers

    def check_connection(self) -> bool:
        try:
            response = self.request(
                "GET",
                f"{self.base_url}/v1/breaches",
                params={"domain": "example.com"},
                headers=self._headers(),
                retries=1,
            )
            ok = getattr(response, "status_code", 0) in (200, 404)
            self.record_run(success=ok, message="" if ok else "XposedOrNot erişimi doğrulanamadı")
            return ok
        except Exception as exc:
            self.record_run(success=False, message=str(exc))
            return False

    def lookup_ioc(self, ioc: IOCInput) -> list[IOCRecord]:
        domain = self._domain_for_query(ioc)
        if not domain:
            raise AdapterConfigError(
                f"XposedOrNot yalnızca domain/URL sorgularını destekliyor: {ioc.ioc_type}"
            )

        response = self.request(
            "GET",
            f"{self.base_url}/v1/breaches",
            params={"domain": domain},
            headers=self._headers(),
        )
        if getattr(response, "status_code", 0) == 404:
            self.record_run(success=True, message="Gösterge XposedOrNot'ta bulunamadı")
            return []

        data = self.json_body(response) or {}
        breaches = data.get("exposedBreaches") or []
        records = [self._breach_to_record(domain, item) for item in breaches if isinstance(item, dict)]
        self.record_run(success=True, message=f"{len(records)} kayıt")
        return records

    def fetch_updates(self, since: Optional[str] = None, **kwargs: Any) -> list[Any]:
        """Doğrulanmış domain'ler için toplu breach kayıtlarını getirir."""
        headers = self._headers(require_key=True)
        request_headers = dict(headers)
        if since:
            request_headers["if-modified-since"] = since

        response = self.request(
            "POST",
            f"{self.base_url}/v1/domain-breaches",
            headers=request_headers,
        )
        data = self.json_body(response) or {}
        metrics = data.get("metrics") or data.get("Metrics") or data
        detail_rows = (
            metrics.get("Breaches_Details")
            or metrics.get("breaches_details")
            or metrics.get("breachesDetails")
            or []
        )
        info_map = (
            metrics.get("Detailed_Breach_Info")
            or metrics.get("detailed_breach_info")
            or metrics.get("detailedBreachInfo")
            or {}
        )

        records: list[dict[str, Any]] = []
        if isinstance(detail_rows, list):
            for row in detail_rows:
                if not isinstance(row, dict):
                    continue
                breach_key = str(row.get("breach") or row.get("breachID") or "").strip()
                extra = self._lookup_detail(info_map, breach_key)
                merged = {**extra, **row}
                merged.setdefault("referenceURL", extra.get("referenceURL"))
                records.append(merged)

        self.record_run(success=True, message=f"{len(records)} kayıt")
        return records

    def normalize_record(self, raw: Any) -> Finding:
        record = raw or {}
        domain = str(record.get("domain") or "").strip().lower() or None
        breach_id = record.get("breach") or record.get("breachID")
        verified = bool(record.get("verified"))
        summary_source = (
            record.get("details")
            or record.get("exposureDescription")
            or record.get("title")
            or record.get("summary")
            or ""
        )
        exposed_data = self._normalize_data_types(record.get("exposedData"))
        reference = (
            record.get("referenceURL")
            or (f"{self.base_url}/?breach={breach_id}" if breach_id else None)
        )

        return Finding(
            finding_id="",
            finding_type=FindingType.BREACH_CLAIM,
            organization=domain,
            matched_domain=domain,
            source_type=self.source_type,
            source_name=self.name,
            source_reference=reference,
            first_seen=parse_timestamp(record.get("breachedDate")) or utcnow(),
            last_checked=utcnow(),
            claimed_event_date=parse_timestamp(record.get("breachedDate")),
            claimed_data_types=exposed_data,
            verification_status=(
                VerificationStatus.CORROBORATED
                if verified
                else VerificationStatus.UNVERIFIED_CLAIM
            ),
            evidence_summary=(
                sanitize_text(summary_source, max_length=600)
                or f"XposedOrNot kaydı: {breach_id or 'breach'}"
            ),
            source_reliability=0.8 if verified else self.source_config.reliability,
            metadata={
                "breach_id": breach_id,
                "verified": verified,
                "industry": record.get("industry"),
                "records_exposed": record.get("exposedRecords"),
                "password_risk": record.get("passwordRisk"),
                "content_digest": content_digest(summary_source or str(record)),
                "untrusted_source": True,
            },
        )

    def _breach_to_record(self, queried_domain: str, breach: dict[str, Any]) -> IOCRecord:
        breach_id = breach.get("breachID")
        verified = bool(breach.get("verified"))
        password_risk = str(breach.get("passwordRisk") or "")
        tags = [breach_id, breach.get("industry"), "breach-intelligence"]
        tags.extend(breach.get("exposedData") or [])
        if verified:
            tags.append("verified")
        if breach.get("sensitive"):
            tags.append("sensitive")
        if password_risk:
            tags.append(password_risk)

        return build_ioc_record(
            value=queried_domain,
            ioc_type=IOCType.DOMAIN,
            source_name=self.name,
            source_type=self.source_type,
            source_reference=(
                breach.get("referenceURL") or f"{self.name}:breach:{breach_id}"
            ),
            first_seen=breach.get("breachedDate"),
            last_seen=breach.get("breachedDate"),
            tags=tags,
            risk_level=self._risk_hint(breach),
            confidence=0.8 if verified else 0.6,
            detail={
                "breach_id": breach_id,
                "verified": verified,
                "sensitive": bool(breach.get("sensitive")),
                "industry": breach.get("industry"),
                "records_exposed": breach.get("exposedRecords"),
                "summary": sanitize_text(breach.get("exposureDescription"), 300),
            },
        )

    @staticmethod
    def _domain_for_query(ioc: IOCInput) -> Optional[str]:
        if ioc.ioc_type == IOCType.DOMAIN:
            return ioc.value
        if ioc.ioc_type == IOCType.URL:
            return (urlsplit(ioc.value).hostname or "").lower() or None
        return None

    @staticmethod
    def _risk_hint(breach: dict[str, Any]) -> str:
        if breach.get("sensitive"):
            return "critical"
        password_risk = str(breach.get("passwordRisk") or "").lower()
        if "plaintext" in password_risk or "easy" in password_risk:
            return "high"
        if breach.get("verified"):
            return "medium"
        return "unassessed"

    @staticmethod
    def _lookup_detail(info_map: Any, breach_key: str) -> dict[str, Any]:
        if not isinstance(info_map, dict) or not breach_key:
            return {}
        if isinstance(info_map.get(breach_key), dict):
            return dict(info_map[breach_key])
        lowered = breach_key.lower()
        for key, value in info_map.items():
            if str(key).lower() == lowered and isinstance(value, dict):
                return dict(value)
        return {}

    @staticmethod
    def _normalize_data_types(values: Any) -> list[str]:
        if values is None:
            return []
        if isinstance(values, str):
            values = [values]
        aliases = {
            "email addresses": "contact",
            "email address": "contact",
            "emails": "contact",
            "passwords": "credentials",
            "password hashes": "credentials",
            "hashes": "credentials",
            "ip addresses": "network",
            "usernames": "account",
            "names": "personal_data",
            "phone numbers": "contact",
        }
        result: list[str] = []
        for value in values:
            key = str(value).strip().lower()
            if not key:
                continue
            mapped = aliases.get(key, key.replace(" ", "_"))
            if mapped not in result:
                result.append(mapped)
        return result
