"""Public registry exports."""

# ruff: noqa: F401

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pact.registry.app import (
        AvoidanceReport,
        AvoidanceReportLabel,
        AvoidanceReportStatus,
        ChallengePurpose,
        ClaimantProfile,
        ClaimVerificationReport,
        DisputeRecord,
        DisputeStatus,
        EvidenceProfile,
        KeyRotationRequest,
        MutationChallenge,
        MutationRequest,
        RegisteredClaim,
        RegistryCertificateAuthority,
        RegistryError,
        RegistryService,
        ReportEvidence,
        SpreadStatus,
        SpreadSummary,
        TrustLabel,
        TrustTier,
        VerificationLabel,
        domain_verification_txt_name,
        domain_verification_txt_value,
        resolve_dns_txt,
    )
    from pact.registry.store import (
        FileRegistryStore,
        PostgresRegistryStore,
        RegistryBatch,
        RegistryEvent,
        RegistryEventType,
        RegistryStore,
        RegistryStoreError,
        SqliteRegistryStore,
        merkle_root,
    )

_EXPORTS = {
    "AvoidanceReport": "pact.registry.app",
    "AvoidanceReportLabel": "pact.registry.app",
    "AvoidanceReportStatus": "pact.registry.app",
    "ChallengePurpose": "pact.registry.app",
    "ClaimantProfile": "pact.registry.app",
    "ClaimVerificationReport": "pact.registry.app",
    "DisputeRecord": "pact.registry.app",
    "DisputeStatus": "pact.registry.app",
    "EvidenceProfile": "pact.registry.app",
    "KeyRotationRequest": "pact.registry.app",
    "MutationChallenge": "pact.registry.app",
    "MutationRequest": "pact.registry.app",
    "RegisteredClaim": "pact.registry.app",
    "RegistryCertificateAuthority": "pact.registry.app",
    "RegistryError": "pact.registry.app",
    "RegistryService": "pact.registry.app",
    "ReportEvidence": "pact.registry.app",
    "SpreadStatus": "pact.registry.app",
    "SpreadSummary": "pact.registry.app",
    "TrustLabel": "pact.registry.app",
    "TrustTier": "pact.registry.app",
    "VerificationLabel": "pact.registry.app",
    "domain_verification_txt_name": "pact.registry.app",
    "domain_verification_txt_value": "pact.registry.app",
    "resolve_dns_txt": "pact.registry.app",
    "FileRegistryStore": "pact.registry.store",
    "PostgresRegistryStore": "pact.registry.store",
    "RegistryBatch": "pact.registry.store",
    "RegistryEvent": "pact.registry.store",
    "RegistryEventType": "pact.registry.store",
    "RegistryStore": "pact.registry.store",
    "RegistryStoreError": "pact.registry.store",
    "SqliteRegistryStore": "pact.registry.store",
    "merkle_root": "pact.registry.store",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> object:
    """Load registry exports on demand."""

    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(name)
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
