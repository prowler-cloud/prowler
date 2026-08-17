from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

OSCAL_VERSION = "1.2.3"
DEFAULT_IMPORT_AP_HREF = "urn:prowler:assessment-plan:default"


@dataclass
class Property:
    name: str
    value: str
    class_: Optional[str] = None
    remarks: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {"name": self.name, "value": self.value}
        if self.class_:
            res["class"] = self.class_
        if self.remarks:
            res["remarks"] = self.remarks
        return res


@dataclass
class Subject:
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
        if self.description:
            res["description"] = self.description
        if self.props:
            res["props"] = [p.to_dict() for p in self.props]
        return res


@dataclass
class RelatedObservation:
    observation_uuid: str

    def to_dict(self) -> dict[str, Any]:
        return {"observation-uuid": self.observation_uuid}


@dataclass
class OscalFinding:
    finding_uuid: str
    title: str
    description: str
    collected: str
    props: List[Property] = field(default_factory=list)
    related_observations: List[RelatedObservation] = field(default_factory=list)
    remarks: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "target": {"type": "statement-id", "target-id": self.finding_uuid},
            "title": self.title,
            "description": self.description,
            "collected": self.collected,
            "related-observations": [ro.to_dict() for ro in self.related_observations],
        }
        if self.props:
            res["props"] = [p.to_dict() for p in self.props]
        if self.remarks:
            res["remarks"] = self.remarks
        return res


@dataclass
class Observation:
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
            "observation-uuid": self.observation_uuid,
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
            "observations": [o.to_dict() for o in self.observations],
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.end:
            res["end"] = self.end
        if self.props:
            res["props"] = [p.to_dict() for p in self.props]
        return res


@dataclass
class Metadata:
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
    assessment_results: AssessmentResults = field(default_factory=AssessmentResults)

    def to_dict(self) -> dict[str, Any]:
        return {"assessment-results": self.assessment_results.to_dict()}
