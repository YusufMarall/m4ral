"""ThreatFox (abuse.ch) adaptörü (PRD 7.2).

Zararlı yazılımlarla ilişkili IOC kayıtları. Ücretsiz topluluk API'si bir
`Auth-Key` gerektirir ve kullanım koşullarına uyulması zorunludur.
"""

from __future__ import annotations

from typing import Any

from models import IOCInput, IOCRecord, SourceCategory, SourceType
from core.normalizer import build_ioc_record, coerce_risk_level, parse_timestamp

from .base import (
    CAP_CONNECTION_CHECK,
    CAP_IOC_LOOKUP,
    AdapterConfigError,
    AdapterError,
    BaseAdapter,
)

THREATFOX_DEFAULT_URL = "https://threatfox-api.abuse.ch/api/v1/"

#: Kaynağın bildirdiği tehdit türlerinin risk karşılıkları.
_THREAT_TYPE_RISK = {
    "botnet_cc": "high",
    "payload_delivery": "high",
    "payload": "high",
    "malware_download": "high",
    "clickfix": "medium",
}


class ThreatFoxAdapter(BaseAdapter):
    adapter_name = "threatfox"
    source_type = SourceType.IOC_FEED
    default_category = SourceCategory.STRUCTURED_API
    capabilities = {CAP_IOC_LOOKUP, CAP_CONNECTION_CHECK}
    requires_api_key = True

    @property
    def api_url(self) -> str:
        return str(self.setting("url", THREATFOX_DEFAULT_URL))

    def _headers(self) -> dict[str, str]:
        key = self.secret()
        if not key:
            raise AdapterConfigError(
                "ThreatFox için API anahtarı gerekli. .env dosyasında THREATFOX_API_KEY tanımlayın."
            )
        return {"Auth-Key": key, "Content-Type": "application/json", "Accept": "application/json"}

    def check_connection(self) -> bool:
        try:
            headers = self._headers()
            response = self.request(
                "POST",
                self.api_url,
                json={"query": "get_ioc", "search_term": "1.1.1.1"},
                headers=headers,
                retries=1,
            )
            ok = getattr(response, "status_code", 0) == 200
            self.record_run(success=ok, message="" if ok else "ThreatFox erişimi doğrulanamadı")
            return ok
        except Exception as exc:
            self.record_run(success=False, message=str(exc))
            return False

    def lookup_ioc(self, ioc: IOCInput) -> list[IOCRecord]:
        payload = {"query": "search_ioc", "search_term": ioc.value, "exact_match": True}
        response = self.request("POST", self.api_url, json=payload, headers=self._headers())
        data = self.json_body(response)
        query_status = str(data.get("query_status") or "").lower()

        if query_status in ("no_result", "illegal_search_term"):
            self.record_run(success=True, message="Gösterge ThreatFox'ta bulunamadı")
            return []
        if query_status != "ok":
            raise AdapterError(f"ThreatFox beklenmeyen sorgu durumu: {query_status or 'bilinmiyor'}")

        entries = data.get("data") or []
        if isinstance(entries, dict):  # tek kayıt dönen yanıt biçimi
            entries = [entries]

        records = [self._to_record(ioc, entry) for entry in entries if isinstance(entry, dict)]
        self.record_run(success=True, message=f"{len(records)} kayıt")
        return records

    def _to_record(self, ioc: IOCInput, entry: dict[str, Any]) -> IOCRecord:
        confidence_level = entry.get("confidence_level")
        try:
            confidence = max(0.0, min(1.0, float(confidence_level) / 100.0))
        except (TypeError, ValueError):
            confidence = None

        tags = list(entry.get("tags") or [])
        for field in ("malware_printable", "malware", "threat_type"):
            if entry.get(field):
                tags.append(str(entry[field]))

        risk_hint = _THREAT_TYPE_RISK.get(str(entry.get("threat_type", "")).lower())
        return build_ioc_record(
            value=entry.get("ioc") or ioc.value,
            ioc_type=ioc.ioc_type,
            source_name=self.name,
            source_type=self.source_type,
            source_reference=f"threatfox:{entry.get('id')}",
            first_seen=parse_timestamp(entry.get("first_seen_utc")),
            last_seen=parse_timestamp(entry.get("last_seen_utc")),
            tags=tags,
            risk_level=coerce_risk_level(risk_hint or confidence_level),
            confidence=confidence,
            detail={
                "threat_type": entry.get("threat_type"),
                "malware": entry.get("malware_printable") or entry.get("malware"),
                "reporter": entry.get("reporter"),
                "reference": entry.get("reference"),
                "confidence_level": confidence_level,
            },
        )
