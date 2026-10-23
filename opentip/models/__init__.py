"""Ortak veri modelleri (IOC, bulgu, kaynak).

Model'ler PRD Bölüm 10'daki ortak veri modelini temel alır. Tüm modüller
(IOC Intelligence, Breach Intelligence, Dark Web Monitoring) aynı kaynak,
zaman ve kanıt alanlarını kullanır.
"""

from .enums import (
    VERIFICATION_TRANSITIONS,
    CatalogNetwork,
    CatalogStatus,
    ChangeType,
    FindingType,
    IOCType,
    RiskLevel,
    RunStatus,
    SourceCategory,
    SourceStatus,
    SourceType,
    VerificationStatus,
    can_transition,
)
from .catalog import CatalogEntry, CatalogSync
from .finding import Alert, AnalystNote, Evidence, Finding
from .ioc import IOCInput, IOCRecord, IOCSourceResult, AnalysisResult, utcnow
from .source import SourceConfig, SourceHealth, SourceRun

__all__ = [
    # enums
    "IOCType",
    "SourceType",
    "SourceCategory",
    "SourceStatus",
    "RunStatus",
    "FindingType",
    "VerificationStatus",
    "RiskLevel",
    "CatalogNetwork",
    "CatalogStatus",
    "ChangeType",
    "VERIFICATION_TRANSITIONS",
    "can_transition",
    # catalog
    "CatalogEntry",
    "CatalogSync",
    # ioc
    "IOCInput",
    "IOCRecord",
    "IOCSourceResult",
    "AnalysisResult",
    "utcnow",
    # finding
    "Finding",
    "Evidence",
    "Alert",
    "AnalystNote",
    # source
    "SourceConfig",
    "SourceRun",
    "SourceHealth",
]
