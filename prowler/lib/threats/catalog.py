"""Load the signatures in force for a scan, and match images against them."""

from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional

import yaml
from pydantic import ValidationError

from prowler.lib.logger import logger
from prowler.lib.threats.models import (
    REGEX_TIMEOUT,
    SEVERITY_ORDER,
    ImageRule,
    ThreatMatch,
    ThreatSignature,
)

BUILTIN_DIR = Path(__file__).parent / "signatures"

#: Scan configuration key holding tenant-supplied signatures, per provider.
AUDIT_CONFIG_KEY = "threat_signatures"


@lru_cache(maxsize=1)
def builtin_signatures() -> tuple:
    """Every signature shipped with Prowler, validated once per process."""
    signatures = []
    for path in sorted(BUILTIN_DIR.glob("*.yaml")):
        try:
            signature = ThreatSignature.model_validate(
                yaml.safe_load(path.read_text(encoding="utf-8"))
            )
            if signature.id != path.stem:
                raise ValueError(f"id {signature.id!r} does not match the file name")
            signatures.append(signature)
        except (ValidationError, ValueError, yaml.YAMLError) as error:
            # A broken built-in is a release bug; skip it rather than fail the scan.
            logger.error(f"Threat signature {path.name} is invalid: {error}")
    return tuple(signatures)


def load_signatures(audit_config: Optional[dict] = None) -> list[ThreatSignature]:
    """Built-in signatures plus the ones the scan configuration supplies.

    A supplied signature with the same id as a built-in replaces it, so a
    tenant can tighten a rule before the next release ships. An invalid
    supplied signature is logged and skipped: the SDK is lenient at runtime,
    and Prowler Cloud already rejects it when the configuration is saved.
    """
    by_id = {signature.id: signature for signature in builtin_signatures()}
    supplied = (audit_config or {}).get(AUDIT_CONFIG_KEY) or []
    if not isinstance(supplied, list):
        logger.error(f"{AUDIT_CONFIG_KEY} must be a list; ignoring it")
        supplied = []
    for index, raw in enumerate(supplied):
        try:
            signature = ThreatSignature.model_validate(raw)
        except ValidationError as error:
            logger.error(
                f"{AUDIT_CONFIG_KEY}[{index}] is invalid and was skipped: {error}"
            )
            continue
        by_id[signature.id] = signature
    return list(by_id.values())


def match_rule(
    rule: ImageRule, names: Iterable[str], publisher: Optional[str]
) -> Optional[tuple[str, str]]:
    """``(matched name, provenance)`` when the image carries this rule, else ``None``.

    Args:
        rule: one image rule of a signature.
        names: every name the cloud reports for the image; the first that
            matches wins.
        publisher: who published the image (AMI owner id, marketplace
            publisher, image project), when the cloud says.
    """
    # Azure echoes publishers in whatever case the VM was created with.
    verified = bool(publisher) and publisher.casefold() in {
        listed.casefold() for listed in rule.publishers
    }
    if rule.require_publisher and not verified:
        return None
    for name in names:
        if name and rule.matches_name(name):
            return name, "publisher" if verified else "name"
    return None


def _match_rule_in_time(
    signature: ThreatSignature,
    rule: ImageRule,
    names: list[str],
    publisher: Optional[str],
) -> Optional[tuple[str, str]]:
    """``match_rule``, treating a regex over the time limit as no match.

    One slow pattern must not stop the check for every other instance; it is
    logged with its signature so the catalog or the tenant can fix it.
    """
    try:
        return match_rule(rule, names, publisher)
    except TimeoutError:
        logger.error(
            f"Threat signature {signature.id}: its {rule.cloud} name_regex took "
            f"longer than {REGEX_TIMEOUT}s on an image name and was skipped"
        )
        return None


def match_image(
    signatures: list[ThreatSignature],
    cloud: str,
    names: Iterable[str],
    publisher: Optional[str] = None,
) -> list[tuple[ThreatSignature, str, str]]:
    """Every signature whose rules for ``cloud`` match the image.

    Returns:
        ``(signature, matched name, provenance)`` per matching signature,
        publisher-verified matches first, then worst severity first.
    """
    names = [name for name in names if name]
    found = []
    for signature in signatures:
        hits = [
            hit
            for rule in signature.rules_for(cloud)
            if (hit := _match_rule_in_time(signature, rule, names, publisher))
        ]
        if hits:
            # A publisher-verified rule is stronger evidence than a name-only
            # one, wherever it sits in the signature.
            found.append((signature, *min(hits, key=lambda hit: hit[1] != "publisher")))
    found.sort(
        key=lambda m: (
            m[2] != "publisher",
            SEVERITY_ORDER.index(m[0].severity),
            m[0].id,
        )
    )
    return found


def to_match(
    signature: ThreatSignature, image: str, provenance: str, **observed
) -> ThreatMatch:
    """The finding payload for one matched signature.

    ``observed`` carries what the check saw on the host; ``exposure_port``
    among it names the port found open, and defaults to the first one the
    signature lists.
    """
    exposure = signature.exposure
    if exposure:
        observed.setdefault("exposure_port", exposure.ports[0])
    return ThreatMatch(
        id=signature.id,
        title=signature.title,
        cves=signature.cves,
        severity=signature.severity,
        image=image,
        provenance=provenance,
        credential_required=signature.credential_required,
        impact=signature.impact,
        remediation=signature.remediation,
        exposure_ports=list(exposure.ports) if exposure else [],
        exposure_protocol=exposure.protocol if exposure else None,
        **observed,
    )


def describe_matches(matches: list[ThreatMatch]) -> str:
    """One line per finding: each threat, its CVEs, and how strong the evidence is."""
    parts = []
    for match in matches:
        cves = f" ({', '.join(match.cves)})" if match.cves else ""
        evidence = (
            "publisher-verified image"
            if match.provenance == "publisher"
            else "image name only"
        )
        exposure = ""
        if match.exposed_to_internet:
            protocol = (match.exposure_protocol or "tcp").upper()
            exposure = f", {protocol} {match.exposure_port} open to the internet"
        parts.append(f"{match.title}{cves} [{evidence}{exposure}]")
    return "; ".join(parts)
