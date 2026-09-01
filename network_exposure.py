"""Context-aware analysis of discovered network services.

The module treats network discovery as evidence, not a verdict. It compares
observed services with an expected asset/service baseline and reports both
assessment status and evidence gaps for analyst review.
"""

import ipaddress
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ServiceObservation:
    ip: str
    port: int
    protocol: str
    service: str

    def __post_init__(self) -> None:
        if not isinstance(self.ip, str):
            raise ValueError("Observation IP address must be a string")
        try:
            ipaddress.ip_address(self.ip)
        except ValueError as exc:
            raise ValueError(f"Invalid observation IP address: {self.ip!r}") from exc
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError(f"Invalid observation port: {self.port!r}")
        if not isinstance(self.protocol, str) or self.protocol.strip().lower() not in {"tcp", "udp"}:
            raise ValueError(f"Unsupported observation protocol: {self.protocol!r}")
        if not isinstance(self.service, str) or not self.service.strip():
            raise ValueError("Observation service must be a non-empty string")


@dataclass(frozen=True)
class AssetContext:
    owner: str
    role: str
    criticality: str
    authorised: bool
    expected_services: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.authorised, bool):
            raise ValueError("AssetContext.authorised must be a boolean")
        if not isinstance(self.expected_services, frozenset):
            raise ValueError("AssetContext.expected_services must be a frozenset")
        if not all(isinstance(item, str) and item.strip() for item in self.expected_services):
            raise ValueError("AssetContext.expected_services must contain non-empty strings")


def _service_key(observation: ServiceObservation) -> str:
    """Return the normalised protocol/port key used for baseline comparison."""
    return f"{observation.protocol.strip().lower()}/{observation.port}"


def assess_service(observation: ServiceObservation, context: AssetContext | None) -> dict:
    """Return a conservative analyst assessment without declaring compromise.

    Confidence describes how strongly the *available context* supports the
    assessment; it is not a probability that the host is compromised.
    """
    service_key = _service_key(observation)

    if context is None:
        return {
            "status": "insufficient_evidence",
            "confidence": "low",
            "reason": "Asset context is unknown.",
            "evidence_gaps": [
                "asset owner",
                "business role",
                "authorisation",
                "expected service baseline",
            ],
            "recommended_action": "Identify and verify the asset owner and business purpose before classification.",
        }

    if not context.authorised:
        return {
            "status": "investigate",
            "confidence": "medium",
            "reason": "Asset is not marked as authorised in the synthetic inventory.",
            "evidence_gaps": [
                "asset ownership verification",
                "asset disposition",
                "business justification",
            ],
            "recommended_action": "Verify ownership and authorised status before deciding whether remediation is required.",
        }

    expected_services = {item.strip().lower() for item in context.expected_services}
    if service_key in expected_services:
        return {
            "status": "expected",
            "confidence": "high",
            "reason": "Observed service matches the authorised service baseline.",
            "evidence_gaps": [],
            "recommended_action": "Record the service as expected and continue normal monitoring/change management.",
        }

    return {
        "status": "investigate",
        "confidence": "medium",
        "reason": "Service is exposed but is not present in the expected service baseline.",
        "evidence_gaps": [
            "business justification",
            "service owner",
            "exposure scope",
            "configuration/version review",
        ],
        "recommended_action": "Verify the service owner, business purpose and exposure scope before deciding on remediation.",
    }


def assess_observations(
    observations: Iterable[ServiceObservation], inventory: dict[str, AssetContext]
) -> list[dict]:
    """Assess observations against an asset inventory."""
    return [
        {
            "observation": observation,
            "assessment": assess_service(observation, inventory.get(observation.ip)),
        }
        for observation in observations
    ]
