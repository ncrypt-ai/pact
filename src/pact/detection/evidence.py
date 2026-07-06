"""Evidence package export for local probe analysis."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from pact.canonical import canonical_json
from pact.crypto import base64url_encode, sign_es256
from pact.detection.probes import ProbeResponse, ProbeSet
from pact.detection.statistics import ProbeAnalysisReport
from pact.identity import ClaimantIdentity


@dataclass(frozen=True, slots=True)
class ProbeEvidenceSignature:
    """Signature over a probe evidence package."""

    key_id: str
    value: str
    algorithm: str = "ES256"

    def to_dict(self) -> dict[str, str]:
        """Serialize the evidence signature."""

        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> ProbeEvidenceSignature:
        """Read an evidence signature from exported data."""

        signature = cls(
            key_id=_required_string(value, "key_id"),
            value=_required_string(value, "value"),
            algorithm=_required_string(value, "algorithm"),
        )
        if signature.algorithm != "ES256":
            raise ValueError(
                "probe evidence signature algorithm must be ES256"
            )
        return signature


@dataclass(frozen=True, slots=True)
class ProbeEvidencePackage:
    """Exportable local evidence package for training-use analysis."""

    probe_set: ProbeSet
    responses: tuple[ProbeResponse, ...]
    analysis: ProbeAnalysisReport
    exported_at: str
    package_digest: str
    signature: ProbeEvidenceSignature | None = None

    @classmethod
    def create(
        cls,
        *,
        probe_set: ProbeSet,
        responses: tuple[ProbeResponse, ...],
        analysis: ProbeAnalysisReport,
        signer: ClaimantIdentity | None = None,
        exported_at: datetime | None = None,
    ) -> ProbeEvidencePackage:
        """Assemble an exportable evidence package."""

        timestamp = (exported_at or datetime.now(UTC)).replace(microsecond=0)
        unsigned = cls(
            probe_set=probe_set,
            responses=responses,
            analysis=analysis,
            exported_at=timestamp.isoformat(),
            package_digest="",
        )
        digest = unsigned.compute_digest()
        signature = None
        if signer is not None:
            signature = ProbeEvidenceSignature(
                key_id=signer.key_id,
                value=sign_es256(
                    signer.private_key, unsigned.canonical_body()
                ),
            )
        return cls(
            probe_set=probe_set,
            responses=responses,
            analysis=analysis,
            exported_at=unsigned.exported_at,
            package_digest=digest,
            signature=signature,
        )

    def with_signature(self, signer: ClaimantIdentity) -> ProbeEvidencePackage:
        """Attach a claimant signature without changing the package body."""

        return ProbeEvidencePackage(
            probe_set=self.probe_set,
            responses=self.responses,
            analysis=self.analysis,
            exported_at=self.exported_at,
            package_digest=self.package_digest,
            signature=ProbeEvidenceSignature(
                key_id=signer.key_id,
                value=sign_es256(signer.private_key, self.canonical_body()),
            ),
        )

    def body(self) -> dict[str, object]:
        """Data covered by the package digest and optional signature."""

        return {
            "probe_set": self.probe_set.to_dict(),
            "responses": [response.to_dict() for response in self.responses],
            "analysis": self.analysis.to_dict(),
            "exported_at": self.exported_at,
        }

    def canonical_body(self) -> bytes:
        """Canonical bytes for digesting and signing."""

        return canonical_json(self.body())

    def compute_digest(self) -> str:
        """Base64url SHA-256 digest of the canonical package body."""

        return base64url_encode(hashlib.sha256(self.canonical_body()).digest())

    def to_dict(self) -> dict[str, object]:
        """Serialize the evidence package for export."""

        result = self.body()
        result["package_digest"] = self.package_digest
        if self.signature is not None:
            result["signature"] = self.signature.to_dict()
        return result

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> ProbeEvidencePackage:
        """Load an exported package and verify its digest."""

        probe_set_value = value.get("probe_set")
        responses_value = value.get("responses")
        analysis_value = value.get("analysis")
        if not isinstance(probe_set_value, dict):
            raise ValueError("probe_set must be an object")
        if not isinstance(responses_value, list):
            raise ValueError("responses must be an array")
        if not isinstance(analysis_value, dict):
            raise ValueError("analysis must be an object")
        signature_value = value.get("signature")
        signature = None
        if signature_value is not None:
            if not isinstance(signature_value, dict):
                raise ValueError("signature must be an object")
            signature = ProbeEvidenceSignature.from_dict(
                cast(dict[str, object], signature_value)
            )
        result = cls(
            probe_set=ProbeSet.from_dict(
                cast(dict[str, object], probe_set_value)
            ),
            responses=tuple(
                ProbeResponse.from_dict(_required_object(item, "response"))
                for item in responses_value
            ),
            analysis=ProbeAnalysisReport.from_dict(
                cast(dict[str, object], analysis_value)
            ),
            exported_at=_required_string(value, "exported_at"),
            package_digest=_required_string(value, "package_digest"),
            signature=signature,
        )
        if result.package_digest != result.compute_digest():
            raise ValueError("evidence package digest does not match")
        return result


def _required_string(value: dict[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{key} must be a nonempty string")
    return item


def _required_object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return cast(dict[str, object], value)
