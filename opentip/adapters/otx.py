"""AlienVault OTX adaptörü (PRD 7.2).

Topluluk tarafından paylaşılan tehdit göstergeleri ve Pulse bilgileri.
Topluluk API'si anahtar olmadan da kısıtlı çalışır; anahtar varsa kullanılır.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from models import IOCInput, IOCRecord, IOCType, SourceCategory, SourceStatus, SourceType
from core.normalizer import build_ioc_record, coerce_risk_level, normalize_tags, parse_timestamp

from .base import CAP_CONNECTION_CHECK, CAP_IOC_LOOKUP, AdapterConfigError, BaseAdapter

OTX_DEFAULT_BASE = "https://otx.alienvault.com/api/v1"

#: IOC türlerinin OTX "indicator section" karşılıkları.
_SECTION_MAP: dict[IOCType, str] = {
    IOCType.IPV4: "IPv4",
    IOCType.IPV6: "IPv6",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.MD5: "file",
    IOCType.SHA1: "file",
    IOCType.SHA256: "file",
}


class OTXAdapter(BaseAdapter):
    adapter_name = "otx"
    source_type = SourceType.IOC_FEED
    default_category = SourceCategory.STRUCTURED_API
    capabilities = {CAP_IOC_LOOKUP, CAP_CONNECTION_CHECK}

    # ------------------------------------------------------------------ #
    @property
    def base_url(self) -> str:
        return str(self.setting("url", OTX_DEFAULT_BASE)).rstrip("/")

    def _headers(self) -> dict[str, str]:
        key = self.secret()
        return {"X-OTX-API-KEY": key} if key else {}

    def check_connection(self) -> bool:
        url = f"{self.base_url}/user/me" if self.secret() else f"{self.base_url}/indicators/domain/example.com/general"
        try:
            response = self.request("GET", url, headers=self._headers(), retries=1)
            ok = getattr(response, "status_code", 0) == 200
            self.record_run(success=ok, message="" if ok else "OTX erişimi doğrulanamadı")
            return ok
        except Exception as exc:
            self.record_run(success=False, message=str(exc))
            return False

    def lookup_ioc(self, ioc: IOCInput) -> list[IOCRecord]:
        section = _SECTION_MAP.get(ioc.ioc_type)  # type: ignore[arg-type]
        if not section:
            raise AdapterConfigError(f"OTX bu IOC türünü desteklemiyor: {ioc.ioc_type}")

        url = f"{self.base_url}/indicators/{section}/{quote(ioc.value, safe='')}/general"
        response = self.request("GET", url, headers=self._headers())
        if getattr(response, "status_code", 0) == 404:
            self.record_run(success=True, message="Gösterge OTX'te bulunamadı")
            return []

        data = self.json_body(response)
        records = self._to_records(ioc, data)
        self.record_run(success=True, message=f"{len(records)} kayıt")
        return records

    # ------------------------------------------------------------------ #
    def _to_records(self, ioc: IOCInput, data: dict[str, Any]) -> list[IOCRecord]:
        pulse_info = data.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        pulse_count = int(pulse_info.get("count") or len(pulses))
        records: list[IOCRecord] = []

        for pulse in pulses:
            # OTX `adversary` alanı bazı yanıtlarda düz metin, bazılarında nesnedir.
            adversary = pulse.get("adversary")
            adversary_name = (
                str(adversary.get("name") or "")
                if isinstance(adversary, dict)
                else str(adversary or "")
            )
            tags = list(pulse.get("tags") or [])
            tags += [m.get("display_name") for m in (pulse.get("malware_families") or []) if m]
            if adversary_name:
                tags.append(adversary_name)
            tags += [a.get("name") for a in (pulse.get("attack_ids") or []) if a]

            risk_source = " ".join(
                str(x)
                for x in [pulse.get("threat_level"), pulse.get("tags"), pulse.get("malware_families")]
                if x
            )
            records.append(
                build_ioc_record(
                    value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    source_name=self.name,
                    source_type=self.source_type,
                    source_reference=f"otx:pulse:{pulse.get('id')}",
                    first_seen=pulse.get("created"),
                    last_seen=pulse.get("modified"),
                    tags=tags,
                    risk_level=coerce_risk_level(risk_source),
                    confidence=min(1.0, max(0.15, pulse_count / 10.0)),
                    detail={
                        "pulse_name": pulse.get("name"),
                        "pulse_id": pulse.get("id"),
                        "adversary": adversary_name or None,
                        "tlp": pulse.get("tlp"),
                        "pulse_count": pulse_count,
                        "tags": normalize_tags(tags),
                    },
                )
            )

        if not records and (data.get("reputation") or 0) > 0:
            # Pulse yok ancak topluluk itibarı pozitif: düşük güvenli tek kayıt.
            records.append(
                build_ioc_record(
                    value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    source_name=self.name,
                    source_type=self.source_type,
                    source_reference=f"otx:reputation:{data.get('reputation')}",
                    last_seen=parse_timestamp(data.get("last_seen")) or None,
                    tags=["otx-reputation"],
                    risk_level=coerce_risk_level("suspicious"),
                    confidence=0.3,
                    detail={"reputation": data.get("reputation"), "pulse_count": pulse_count},
                )
            )

        return records
