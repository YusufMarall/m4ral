"""MISP adaptörü (PRD 7.2, 8.7).

Yapılandırılmış tehdit istihbaratı olayları ve IOC kayıtları. Yalnızca yetkili
erişim ile kullanılır; TLS doğrulaması varsayılan olarak açıktır.
"""

from __future__ import annotations

from typing import Any, Optional

from models import (
    Finding,
    FindingType,
    IOCInput,
    IOCRecord,
    RiskLevel,
    SourceCategory,
    SourceType,
    VerificationStatus,
    utcnow,
)
from core.normalizer import (
    build_ioc_record,
    coerce_risk_level,
    content_digest,
    parse_timestamp,
    sanitize_text,
)

from .base import (
    CAP_CONNECTION_CHECK,
    CAP_FETCH_UPDATES,
    CAP_IOC_LOOKUP,
    AdapterConfigError,
    AdapterError,
    BaseAdapter,
)

#: MISP kategori/attribute türlerinin ortak veri türü karşılıkları (PRD 8.4).
_CATEGORY_MAP: dict[str, str] = {
    "personal data": "personal_data",
    "personal-data": "personal_data",
    "financial fraud": "financial",
    "financial": "financial",
    "credentials": "credentials",
    "credit card": "credit_card",
    "health data": "health",
    "source code": "source_code",
    "external analysis": "external_analysis",
    "payload delivery": "malware",
    "network activity": "network",
}

#: MISP tehdit seviyesi (1-4) → risk seviyesi
_THREAT_LEVEL_MAP = {
    1: RiskLevel.HIGH,
    2: RiskLevel.MEDIUM,
    3: RiskLevel.LOW,
    4: RiskLevel.LOW,
}


class MISPAdapter(BaseAdapter):
    adapter_name = "misp"
    source_type = SourceType.IOC_FEED
    default_category = SourceCategory.STRUCTURED_API
    capabilities = {CAP_IOC_LOOKUP, CAP_CONNECTION_CHECK, CAP_FETCH_UPDATES}
    requires_api_key = True
    required_settings = ("url",)

    # ------------------------------------------------------------------ #
    @property
    def base_url(self) -> str:
        return self.require_config("url").rstrip("/")

    def _headers(self) -> dict[str, str]:
        key = self.secret()
        if not key:
            raise AdapterConfigError(
                "MISP için API anahtarı gerekli. .env dosyasında MISP_API_KEY tanımlayın."
            )
        return {
            "Authorization": key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @property
    def verify_tls(self) -> bool:
        return bool(getattr(self.settings, "misp_verify_tls", True))

    def _base_kwargs(self) -> dict[str, Any]:
        return {"headers": self._headers(), "verify": self.verify_tls}

    # ------------------------------------------------------------------ #
    def check_connection(self) -> bool:
        try:
            response = self.request(
                "GET", f"{self.base_url}/users/view/me", retries=1, **self._base_kwargs()
            )
            ok = getattr(response, "status_code", 0) == 200
            self.record_run(success=ok, message="" if ok else "MISP erişimi doğrulanamadı")
            return ok
        except Exception as exc:
            self.record_run(success=False, message=str(exc))
            return False

    def lookup_ioc(self, ioc: IOCInput) -> list[IOCRecord]:
        payload = {
            "value": ioc.value,
            "returnFormat": "json",
            "limit": 50,
            "page": 1,
            "enforceWarninglist": True,
        }
        response = self.request(
            "POST", f"{self.base_url}/attributes/restSearch", json=payload, **self._base_kwargs()
        )
        data = self.json_body(response)
        attributes = ((data.get("response") or {}).get("Attribute")) or []
        records = [self._attribute_to_record(ioc, attr) for attr in attributes]
        self.record_run(success=True, message=f"{len(records)} kayıt")
        return records

    def fetch_updates(self, since: Optional[str] = None, last: str = "7d", limit: int = 200) -> list[Any]:
        """Son dönemde yayımlanan MISP olaylarını getirir."""
        payload: dict[str, Any] = {
            "returnFormat": "json",
            "limit": limit,
            "page": 1,
            "enforceWarninglist": True,
        }
        if since:
            payload["timestamp"] = since
        else:
            payload["last"] = last

        response = self.request(
            "POST", f"{self.base_url}/events/restSearch", json=payload, **self._base_kwargs()
        )
        data = self.json_body(response)
        events = data.get("response") or []
        normalized: list[Any] = []
        for item in events:
            event = item.get("Event") if isinstance(item, dict) else None
            if event:
                normalized.append(event)
        self.record_run(success=True, message=f"{len(normalized)} olay")
        return normalized

    def normalize_record(self, raw: Any) -> Finding:
        """MISP olayını ortak bulgu modeline dönüştürür.

        Olay bilgisi tek başına doğrulama sağlamaz; bulgu `unverified_claim`
        durumunda oluşturulur (PRD 8.5).
        """
        event = raw or {}
        info = sanitize_text(event.get("info"), max_length=600)
        event_id = event.get("id") or event.get("uuid") or "unknown"

        data_types: list[str] = []
        org_names: set[str] = set()
        for attr in event.get("Attribute") or []:
            category = str(attr.get("category") or "").strip().lower()
            if category in _CATEGORY_MAP:
                mapped = _CATEGORY_MAP[category]
                if mapped not in data_types:
                    data_types.append(mapped)
            if attr.get("value") and "domain" in str(attr.get("type", "")).lower():
                org_names.add(str(attr["value"]).split("|")[-1].strip().lower())

        matched_domain = sorted(org_names)[0] if org_names else None
        threat_level = event.get("threat_level_id")
        try:
            risk = _THREAT_LEVEL_MAP.get(int(threat_level), RiskLevel.UNASSESSED)
        except (TypeError, ValueError):
            risk = coerce_risk_level(event.get("threat_level_id"))

        summary = f"MISP olayı #{event_id}: {info}" if info else f"MISP olayı #{event_id}"
        return Finding(
            finding_id="",
            finding_type=FindingType.BREACH_CLAIM,
            matched_domain=matched_domain,
            source_type=self.source_type,
            source_name=self.name,
            source_reference=f"misp:event:{event_id}",
            first_seen=parse_timestamp(event.get("publish_timestamp") or event.get("timestamp")) or utcnow(),
            last_checked=utcnow(),
            claimed_event_date=parse_timestamp(event.get("date")),
            claimed_data_types=data_types,
            verification_status=VerificationStatus.UNVERIFIED_CLAIM,
            risk_level=risk,
            evidence_summary=summary,
            source_reliability=self.source_config.reliability,
            metadata={
                "event_uuid": event.get("uuid"),
                "event_info": info,
                "content_digest": content_digest(summary),
                "attribute_count": len(event.get("Attribute") or []),
                "origin": "MISP",
            },
        )

    # ------------------------------------------------------------------ #
    def _attribute_to_record(self, ioc: IOCInput, attr: dict[str, Any]) -> IOCRecord:
        tags = [t.get("name") for t in (attr.get("Tag") or []) if isinstance(t, dict)]
        event = attr.get("Event") or {}
        return build_ioc_record(
            value=attr.get("value") or ioc.value,
            ioc_type=ioc.ioc_type,
            source_name=self.name,
            source_type=self.source_type,
            source_reference=f"misp:attribute:{attr.get('id')}",
            first_seen=parse_timestamp(event.get("date")),
            last_seen=parse_timestamp(attr.get("timestamp")),
            tags=tags + [attr.get("category") or ""],
            risk_level=coerce_risk_level(
                _THREAT_LEVEL_MAP.get(_safe_int(event.get("threat_level_id")), RiskLevel.UNASSESSED)
            ),
            confidence=0.7 if attr.get("to_ids") else 0.4,
            detail={
                "attribute_type": attr.get("type"),
                "category": attr.get("category"),
                "event_id": event.get("id"),
                "event_info": sanitize_text(event.get("info"), 300),
                "to_ids": bool(attr.get("to_ids")),
            },
        )


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
