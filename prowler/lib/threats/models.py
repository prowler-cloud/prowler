"""Threat signatures: an emerging vulnerability described as data.

A signature says which machine images carry the vulnerability, which network
exposure makes it reachable, what an attacker gains, and how to fix it. The
emerging-threat checks match every compute instance against the signatures in
force for a scan; Prowler Cloud folds the matches into Exploitability issues.

A new threat therefore ships as a signature, not as code: a YAML file in
``prowler/lib/threats/signatures/`` for everyone, or an entry under
``threat_signatures`` in a provider's scan configuration for one tenant.
"""

import re
from datetime import date
from functools import lru_cache
from typing import Annotated, Literal, Optional

import regex
from packaging.version import InvalidVersion, Version
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

#: Persisted inside an issue's pattern id (``<cloud>_emerging_threat:<id>``),
#: which is capped at 64 characters, so the id is a short slug.
SIGNATURE_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$"

SUPPORTED_CLOUDS = ("aws", "azure", "gcp")

Severity = Literal["critical", "high", "medium", "low"]

#: Worst first, matching ``Check_Report`` severities.
SEVERITY_ORDER = ("critical", "high", "medium", "low")


#: Image names are short (an AMI name is at most 128 characters); anything
#: longer is cut before matching so a tenant-supplied pattern cannot be fed a
#: pathological input.
MAX_IMAGE_NAME = 1024

#: Seconds one ``name_regex`` may spend on one image name. Signatures come from
#: catalogs and tenants, and run on every image of every scanned account, so
#: they use the ``regex`` engine (which defuses most backtracking patterns) and
#: a pattern that is still slow raises ``TimeoutError`` instead of stalling.
REGEX_TIMEOUT = 0.1


@lru_cache(maxsize=1024)
def _compiled(pattern: str, ignore_case: bool = False):
    """A rule's ``name_regex``, compiled once per scan for every image it is tried on."""
    return regex.compile(pattern, regex.IGNORECASE if ignore_case else 0)


def parse_version(value: str) -> Version:
    """A release version, accepting dashes for dots.

    GCP image names cannot hold dots, so an imported image of release 3.20.3
    is named ``<distro>-3-20-3-...``.
    """
    return Version(value.replace("-", "."))


def _version(value: Optional[str]) -> Optional[str]:
    if value is not None:
        try:
            parse_version(value)
        except InvalidVersion as error:
            raise ValueError(f"not a version: {value!r}") from error
    return value


VersionString = Annotated[Optional[str], AfterValidator(_version)]


class VersionRange(BaseModel):
    """Affected versions, both bounds inclusive; an open bound is unbounded."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    min: VersionString = None
    max: VersionString = None

    @model_validator(mode="after")
    def _bounded(self) -> "VersionRange":
        if self.min is None and self.max is None:
            raise ValueError("a version range needs min, max or both")
        if self.min and self.max and parse_version(self.min) > parse_version(self.max):
            raise ValueError(f"min {self.min} is above max {self.max}")
        return self

    def contains(self, version: Version) -> bool:
        if self.min and version < parse_version(self.min):
            return False
        if self.max and version > parse_version(self.max):
            return False
        return True


class RuleExamples(BaseModel):
    """Image names the rule must and must not match, checked when it is loaded.

    A signature reaches every scanned account, so its regex and version ranges
    are proven against real names before it ships: a built-in or tenant
    signature whose examples disagree with its rule is rejected.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    matches: list[str] = Field(default_factory=list, max_length=50)
    misses: list[str] = Field(default_factory=list, max_length=50)


class ImageRule(BaseModel):
    """Which images of one cloud carry the vulnerability.

    ``name_regex`` runs against the image name the cloud reports: the AMI name
    on AWS, the gallery image definition, custom image or marketplace offer/SKU
    on Azure, and the boot disk's source image on GCP; Azure names match in
    any case (see ``matches_name``). A named group
    ``version`` is compared against ``versions`` (or the ``version_min`` /
    ``version_max`` shorthand for a single range); the image is affected when
    the version falls in any range. Several ranges express per-branch fixes,
    for example 3.21.0-3.21.9 and 3.22.0-3.22.7 when 3.21.10 and 3.22.8 ship
    the patch.

    ``publishers`` proves where the image came from: AMI owner account ids on
    AWS, marketplace publishers on Azure, and image projects on GCP. A match
    whose publisher is listed is reported as ``publisher`` provenance; a match
    on the name alone, as ``name`` provenance, which is weaker evidence because
    anybody can name an image anything.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    cloud: Literal["aws", "azure", "gcp"]
    name_regex: str = Field(min_length=1, max_length=512)
    publishers: list[str] = Field(default_factory=list, max_length=50)
    require_publisher: bool = Field(
        default=False,
        description="Ignore name-only matches; only publisher-verified images match.",
    )
    version_min: VersionString = None
    version_max: VersionString = None
    versions: list[VersionRange] = Field(default_factory=list, max_length=50)
    examples: Optional[RuleExamples] = None

    @field_validator("name_regex")
    @classmethod
    def _compiles(cls, value: str) -> str:  # noqa: F841
        try:
            _compiled(value)
        except regex.error as error:
            raise ValueError(f"name_regex does not compile: {error}") from error
        return value

    @property
    def ranges(self) -> list[VersionRange]:
        """Every affected range: ``versions`` plus the min/max shorthand."""
        shorthand = (
            [VersionRange(min=self.version_min, max=self.version_max)]
            if self.version_min or self.version_max
            else []
        )
        return [*self.versions, *shorthand]

    def matches_name(self, name: str) -> bool:
        """Whether an image name carries this rule, publisher aside.

        Azure names ignore case: Azure treats resource names, offers and SKUs
        case-insensitively and reports them in whatever case the VM was
        created with. AMI and GCP image names are case-sensitive.

        Raises:
            TimeoutError: the regex took longer than ``REGEX_TIMEOUT``.
        """
        found = _compiled(self.name_regex, self.cloud == "azure").search(
            name[:MAX_IMAGE_NAME], timeout=REGEX_TIMEOUT
        )
        if not found:
            return False
        ranges = self.ranges
        if not ranges:
            return True
        version = found.groupdict().get("version")
        if not version:
            return False
        try:
            parsed = parse_version(version)
        except InvalidVersion:
            return False
        return any(version_range.contains(parsed) for version_range in ranges)

    @model_validator(mode="after")
    def _consistent(self) -> "ImageRule":
        if self.ranges and "version" not in _compiled(self.name_regex).groupindex:
            raise ValueError(
                "version ranges need a (?P<version>...) group in name_regex"
            )
        if self.require_publisher and not self.publishers:
            raise ValueError("require_publisher needs at least one publisher")
        if self.examples:
            try:
                wrong = [n for n in self.examples.matches if not self.matches_name(n)]
                matched_misses = [
                    n for n in self.examples.misses if self.matches_name(n)
                ]
            except TimeoutError as error:
                # Pydantic only reports ValueError as a validation error.
                raise ValueError(
                    f"the {self.cloud} rule's name_regex takes too long to match "
                    f"its examples (over {REGEX_TIMEOUT}s); simplify the pattern"
                ) from error
            wrong += matched_misses
            if wrong:
                # A supplied signature that fails here is logged and skipped,
                # so the message has to say why a miss now matches.
                hint = (
                    " (Azure names match in any case)"
                    if matched_misses and self.cloud == "azure"
                    else ""
                )
                raise ValueError(
                    f"the {self.cloud} rule disagrees with its examples: {wrong}{hint}"
                )
        return self


class Exposure(BaseModel):
    """The network path that makes the vulnerability reachable.

    ``ports`` lists every port the vulnerable service listens on (an appliance
    often answers on both 443 and 8443); ``port`` is shorthand for one.
    """

    model_config = ConfigDict(extra="forbid")

    protocol: Literal["tcp", "udp"] = "tcp"
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(
        min_length=1, max_length=16
    )

    @model_validator(mode="before")
    @classmethod
    def _port_shorthand(cls, data):  # noqa: F841
        if isinstance(data, dict) and "port" in data:
            data = dict(data)
            port = data.pop("port")
            if "ports" in data:
                raise ValueError("give port or ports, not both")
            data["ports"] = [port]
        return data


class ThreatSignature(BaseModel):
    """One emerging vulnerability, as data."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(pattern=SIGNATURE_ID_PATTERN)
    title: str = Field(min_length=3, max_length=160)
    cves: list[str] = Field(default_factory=list, max_length=25)
    severity: Severity
    published: Optional[date] = None
    summary: str = Field(min_length=1, max_length=4000)
    references: list[str] = Field(default_factory=list, max_length=25)
    images: list[ImageRule] = Field(min_length=1, max_length=50)
    exposure: Optional[Exposure] = None
    credential_required: bool = Field(
        description="Whether exploiting it still needs a password or key. "
        "An authentication bypass is false.",
    )
    impact: str = Field(
        min_length=1,
        max_length=1000,
        description="What a successful attacker gains, in one sentence.",
    )
    mitigations: list[
        Literal["password_authentication_disabled", "port_not_exposed"]
    ] = Field(
        default_factory=list,
        description="Controls Prowler can observe that break the chain.",
    )
    remediation: str = Field(min_length=1, max_length=4000)

    @field_validator("cves")
    @classmethod
    def _cve_format(cls, values: list[str]) -> list[str]:  # noqa: F841
        for value in values:
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
                raise ValueError(f"not a CVE id: {value!r}")
        return values

    def rules_for(self, cloud: str) -> list[ImageRule]:
        return [rule for rule in self.images if rule.cloud == cloud]


class ThreatMatch(BaseModel):
    """One signature matched on one instance, as stored in the finding."""

    id: str
    title: str
    cves: list[str]
    severity: Severity
    image: str
    provenance: Literal["publisher", "name"]
    credential_required: bool
    impact: str
    remediation: str
    #: Every port the threat's service listens on, and its protocol.
    exposure_ports: list[int] = Field(default_factory=list)
    exposure_protocol: Optional[str] = None
    #: The port found open to the internet when the check could tell, else
    #: the first one the signature names.
    exposure_port: Optional[int] = None
    exposed_to_internet: Optional[bool] = None
    public_route: Optional[bool] = None
    mitigations_observed: list[str] = Field(default_factory=list)
    #: The vulnerability scanner that reports the threat's CVEs on this very
    #: host (for example ``inspector2``), and which of them it reports. An image
    #: match alone proves the image, not the installed build; this proves both.
    confirmed_by: Optional[str] = None
    confirmed_cves: list[str] = Field(default_factory=list)


def worst_severity(matches: list[ThreatMatch]) -> str:
    return min(
        (match.severity for match in matches), key=SEVERITY_ORDER.index, default="low"
    )


def _unique_ids(signatures: list[ThreatSignature]) -> list[ThreatSignature]:
    seen, duplicates = set(), set()
    for signature in signatures:
        (duplicates if signature.id in seen else seen).add(signature.id)
    if duplicates:
        raise ValueError(f"duplicate threat signature ids: {sorted(duplicates)}")
    return signatures


#: The ``threat_signatures`` value of a provider's scan configuration.
ThreatSignatureList = Annotated[list[ThreatSignature], AfterValidator(_unique_ids)]
