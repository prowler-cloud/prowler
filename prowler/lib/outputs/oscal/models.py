from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, List, Optional

OSCAL_VERSION = "1.2.3"
DEFAULT_IMPORT_AP_HREF = "urn:prowler:assessment-plan:default"


@dataclass
class Property:
    """An OSCAL ``property``: a generic name/value pair attachable to most
    OSCAL objects, used here to carry Prowler-specific metadata (check id,
    severity, region, etc.) that has no dedicated field elsewhere.
    """

    name: str
    value: str
    class_: Optional[str] = None
    remarks: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the OSCAL property JSON shape (``class`` is the
        reserved-keyword-safe name for the Python attribute ``class_``)."""
        res: dict[str, Any] = {"name": self.name, "value": self.value}
        if self.class_:
            res["class"] = self.class_
        if self.remarks:
            res["remarks"] = self.remarks
        return res


@dataclass
class Subject:
    """A reference to the resource an observation was made about.

    Serializes to the OSCAL ``subject-reference`` type (assessment-common),
    whose schema is ``additionalProperties: false`` over
    {subject-uuid, type, title, props, links, remarks} -- notably it has no
    ``description`` property, unlike several other OSCAL "subject" shapes.
    """

    subject_uuid: str
    type: str = "component"
    title: str = ""
    description: Optional[str] = None
    props: List[Property] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "subject-uuid": self.subject_uuid,
            "type": self.type,
            "title": self.title,
        }
        if self.props:
            res["props"] = [p.to_dict() for p in self.props]
        return res


@dataclass
class RelatedObservation:
    """A finding's reference to the observation(s) that produced it.

    This is a distinct OSCAL type from ``observation`` itself: its one
    field is genuinely named ``observation-uuid`` (a reference), which
    must equal the target ``Observation``'s own ``uuid``.
    """

    observation_uuid: str

    def to_dict(self) -> dict[str, Any]:
        return {"observation-uuid": self.observation_uuid}


@dataclass
class OscalFinding:
    """An OSCAL ``finding`` (assessment-common): required = uuid, title,
    description, target. ``target`` is itself required to carry
    {type, target-id, status} -- all three were previously missing or wrong:
    target-id was the finding's own uuid (should reference what was actually
    assessed) and status was omitted entirely despite being required.

    There is no ``collected`` property on a finding in the OSCAL schema (that
    field exists only on ``observation``); it is intentionally not emitted.
    """

    finding_uuid: str
    title: str
    description: str
    target_id: str
    target_type: str = "objective-id"
    target_status_state: str = "not-satisfied"
    target_status_reason: Optional[str] = "fail"
    props: List[Property] = field(default_factory=list)
    related_observations: List[RelatedObservation] = field(default_factory=list)
    remarks: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        target_status: dict[str, Any] = {"state": self.target_status_state}
        if self.target_status_reason:
            target_status["reason"] = self.target_status_reason
        res: dict[str, Any] = {
            "uuid": self.finding_uuid,
            "title": self.title,
            "description": self.description,
            "target": {
                "type": self.target_type,
                "target-id": self.target_id,
                "status": target_status,
            },
            "related-observations": [ro.to_dict() for ro in self.related_observations],
        }
        if self.props:
            res["props"] = [p.to_dict() for p in self.props]
        if self.remarks:
            res["remarks"] = self.remarks
        return res


@dataclass
class Observation:
    """An OSCAL ``observation`` (assessment-common): required = uuid,
    description, methods, collected. One Observation is emitted per Prowler
    finding regardless of PASS/FAIL -- it is the full record of the check
    execution; ``OscalFinding`` (FAIL only) references back to it.
    """

    observation_uuid: str
    title: str
    description: str
    collected: str
    methods: List[str] = field(default_factory=lambda: ["automated-test"])
    types: List[str] = field(default_factory=lambda: ["finding"])
    subjects: List[Subject] = field(default_factory=list)
    props: List[Property] = field(default_factory=list)
    remarks: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "uuid": self.observation_uuid,
            "title": self.title,
            "description": self.description,
            "collected": self.collected,
            "methods": self.methods,
            "types": self.types,
            "subjects": [s.to_dict() for s in self.subjects],
        }
        if self.props:
            res["props"] = [p.to_dict() for p in self.props]
        if self.remarks:
            res["remarks"] = self.remarks
        return res


@dataclass
class Result:
    """An OSCAL ``result`` (assessment-ar): required = uuid, title,
    description, start, reviewed-controls. ``reviewed-controls`` was
    previously omitted entirely, despite being unconditionally required --
    not just for findings. Its own required sub-property is
    control-selections (a non-empty array); Prowler evaluates all controls
    it has checks for, so an ``include-all`` selection is emitted by
    default.
    """

    result_uuid: str
    title: str
    description: str
    start: str
    end: Optional[str] = None
    props: List[Property] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    findings: List[OscalFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "uuid": self.result_uuid,
            "title": self.title,
            "description": self.description,
            "start": self.start,
            "reviewed-controls": {"control-selections": [{"include-all": {}}]},
        }
        if self.end:
            res["end"] = self.end
        if self.props:
            res["props"] = [p.to_dict() for p in self.props]
        # Both arrays require minItems: 1 when present -- neither is in
        # `required`, so an empty run (e.g. all-PASS, zero findings) must
        # omit the key entirely rather than emit an empty array.
        if self.observations:
            res["observations"] = [o.to_dict() for o in self.observations]
        if self.findings:
            res["findings"] = [f.to_dict() for f in self.findings]
        return res


@dataclass
class Metadata:
    """The OSCAL ``metadata`` block: document-level title, timestamps,
    version, and the ``oscal-version`` this document conforms to.
    """

    title: str = "Prowler Assessment Results"
    published: str = ""
    last_modified: str = ""
    version: str = "1.0.0"
    oscal_version: str = OSCAL_VERSION
    props: List[Property] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "title": self.title,
            "published": self.published,
            "last-modified": self.last_modified,
            "version": self.version,
            "oscal-version": self.oscal_version,
        }
        if self.props:
            res["props"] = [p.to_dict() for p in self.props]
        return res


@dataclass
class AssessmentResults:
    """The OSCAL ``assessment-results`` object: metadata, a reference to
    the assessment plan (``import-ap``) this run was performed against, and
    the list of ``Result`` runs (Prowler emits exactly one per transform).
    """

    uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: Metadata = field(default_factory=Metadata)
    import_ap_href: str = DEFAULT_IMPORT_AP_HREF
    results: List[Result] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid,
            "metadata": self.metadata.to_dict(),
            "import-ap": {"href": self.import_ap_href},
            "results": [r.to_dict() for r in self.results],
        }


@dataclass
class OscalDocument:
    """The top-level OSCAL document envelope: ``{"assessment-results": ...}``,
    matching the single root key every OSCAL model type document requires."""

    assessment_results: AssessmentResults = field(default_factory=AssessmentResults)

    def to_dict(self) -> dict[str, Any]:
        return {"assessment-results": self.assessment_results.to_dict()}
