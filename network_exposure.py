"""Context-aware analysis of discovered network services.

This module deliberately does not label an open port as malicious. It compares
observed services with an expected asset/service baseline and reports evidence
gaps for analyst review.
"""

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ServiceObservation:
    ip: str
    port: int
    protocol: str
    service: str


@dataclass(frozen=True)
class AssetContext:
    owner: str
    role: str
    criticality: str
    authorised: bool
    expected_services: frozenset[str]


def assess_service(observation: ServiceObservation, context: AssetContext | None) -> dict:
    """Return an evidence-based assessment without declaring compromise."""
    service_key = f"{observation.protocol.lower()}/{observation.port}"

    if context is None:
        return {
            "status": "insufficient_evidence",
            "reason": "Asset context is unknown.",
            "evidence_gaps": ["asset owner", "business role", "authorisation", "expected service baseline"],
        }

    if not context.authorised:
        return {
            "status": "investigate",
            "reason": "Asset is not marked as authorised in the synthetic inventory.",
            "evidence_gaps": ["asset ownership verification", "asset disposition", "business justification"],
        }

    if service_key in context.expected_services:
        return {
            "status": "expected",
            "reason": "Observed service matches the authorised service baseline.",
            "evidence_gaps": [],
        }

    return {
        "status": "investigate",
        "reason": "Service is exposed but is not present in the expected service baseline.",
        "evidence_gaps": ["business justification", "service owner", "exposure scope", "configuration/version review"],
    }


def assess_observations(observations: Iterable[ServiceObservation], inventory: dict[str, AssetContext]) -> list[dict]:
    """Assess observations against an asset inventory."""
    results = []
    for observation in observations:
        assessment = assess_service(observation, inventory.get(observation.ip))
        results.append({"observation": observation, "assessment": assessment})
    return results
