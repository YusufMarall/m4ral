"""OpenTIP çekirdek katmanı: doğrulama, normalizasyon, tekilleştirme, risk ve analiz."""

from .analyzer import AnalysisManager, IOCAdapter
from .deduplicator import (
    deduplicate_records,
    finding_fingerprint,
    fingerprint,
    ioc_fingerprint,
    merge_source_references,
)
from .deepdark import (
    CATEGORY_MAP,
    DEEPDARK_CATEGORIES,
    CatalogCategory,
    DeepDarkCatalogService,
    category_by_key,
    category_label,
    detect_network,
    normalize_status,
    parse_catalog_entries,
    parse_markdown_table,
)
from .finding_manager import FindingManager, FindingOutcome, NullNotifier
from .ioc_validator import (
    IOCValidationError,
    detect_ioc_type,
    extract_indicators,
    is_valid_asset_value,
    normalize_ioc_value,
    refang,
    validate_ioc,
)
from .normalizer import (
    build_ioc_record,
    coerce_risk_level,
    content_digest,
    is_fresh,
    normalize_tags,
    parse_timestamp,
    records_from_text,
    sanitize_text,
)
from .risk_engine import RiskAssessment, RiskEngine, RiskFactor

__all__ = [
    # analyzer
    "AnalysisManager",
    "IOCAdapter",
    # validator
    "IOCValidationError",
    "detect_ioc_type",
    "extract_indicators",
    "is_valid_asset_value",
    "normalize_ioc_value",
    "refang",
    "validate_ioc",
    # normalizer
    "build_ioc_record",
    "coerce_risk_level",
    "content_digest",
    "is_fresh",
    "normalize_tags",
    "parse_timestamp",
    "records_from_text",
    "sanitize_text",
    # deduplicator
    "deduplicate_records",
    "finding_fingerprint",
    "fingerprint",
    "ioc_fingerprint",
    "merge_source_references",
    # kaynak kataloğu (deepdarkCTI)
    "CATEGORY_MAP",
    "DEEPDARK_CATEGORIES",
    "CatalogCategory",
    "DeepDarkCatalogService",
    "category_by_key",
    "category_label",
    "detect_network",
    "normalize_status",
    "parse_catalog_entries",
    "parse_markdown_table",
    # risk
    "RiskAssessment",
    "RiskEngine",
    "RiskFactor",
    # findings
    "FindingManager",
    "FindingOutcome",
    "NullNotifier",
]
