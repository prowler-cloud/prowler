"""Pydantic models for simplified security findings responses."""

from typing import Literal

from pydantic import BaseModel, model_serializer


class CheckRemediation(BaseModel):
    """Remediation information for a security check."""

    cli: str | None = None
    terraform: str | None = None
    recommendation_text: str | None = None
    recommendation_url: str | None = None

    @model_serializer(mode="wrap")
    def _serialize(self, serializer, info):
        """Exclude None and empty string fields."""
        data = serializer(self)
        return {k: v for k, v in data.items() if v is not None and v != ""}


class CheckMetadata(BaseModel):
    """Essential metadata for a security check."""

    check_id: str
    title: str
    description: str
    provider: str
    risk: str | None = None
    service: str
    resource_type: str
    remediation: CheckRemediation | None = None
    related_url: str | None = None
    categories: list[str] | None = None

    @model_serializer(mode="wrap")
    def _serialize(self, serializer, info):
        """Exclude None, empty strings, empty lists, and empty dicts."""
        data = serializer(self)
        result = {}
        for k, v in data.items():
            # Skip None, empty strings, empty lists, and empty dicts
            if v is None or v == "" or v == [] or (isinstance(v, dict) and not v):
                continue
            result[k] = v
        return result

    @classmethod
    def from_api_response(cls, data: dict) -> "CheckMetadata":
        """Transform API check_metadata to simplified format."""
        remediation_data = data.get("remediation", {})
        code = remediation_data.get("code", {})
        recommendation = remediation_data.get("recommendation", {})

        remediation = CheckRemediation(
            cli=code.get("cli") or None,
            terraform=code.get("terraform") or None,
            recommendation_text=recommendation.get("text") or None,
            recommendation_url=recommendation.get("url") or None,
        )

        return cls(
            check_id=data.get("checkid"),
            title=data.get("checktitle"),
            description=data.get("description"),
            provider=data.get("provider"),
            risk=data.get("risk") or None,
            service=data.get("servicename"),
            resource_type=data.get("resourcetype"),
            remediation=remediation,
            related_url=data.get("relatedurl") or None,
            categories=data.get("categories") or None,
        )


class SimplifiedFinding(BaseModel):
    """Simplified security finding with only LLM-relevant information."""

    id: str
    uid: str
    status: Literal["FAIL", "PASS", "MANUAL"]
    severity: Literal["critical", "high", "medium", "low", "informational"]
    check_metadata: CheckMetadata
    status_extended: str | None = None
    delta: Literal["new", "changed"] | None = None
    muted: bool | None = None
    muted_reason: str | None = None

    @model_serializer(mode="wrap")
    def _serialize(self, serializer, info):
        """Exclude None, empty strings, and False booleans."""
        data = serializer(self)
        result = {}
        for k, v in data.items():
            # Skip None and empty strings
            if v is None or v == "":
                continue
            # Skip muted if False (default state, not useful info)
            if k == "muted" and v is False:
                continue
            result[k] = v
        return result

    @classmethod
    def from_api_response(cls, data: dict) -> "SimplifiedFinding":
        """Transform JSON:API finding response to simplified format."""
        attributes = data.get("attributes", {})
        check_metadata = attributes.get("check_metadata", {})

        return cls(
            id=data.get("id"),
            uid=attributes.get("uid"),
            status=attributes.get("status"),
            severity=attributes.get("severity"),
            check_metadata=CheckMetadata.from_api_response(check_metadata),
            status_extended=attributes.get("status_extended") or None,
            delta=attributes.get("delta"),
            muted=attributes.get("muted") if attributes.get("muted") else None,
            muted_reason=attributes.get("muted_reason"),
        )


class FindingsListResponse(BaseModel):
    """Simplified response for findings list queries."""

    findings: list[SimplifiedFinding]
    total_count: int = 0
    page_number: int = 1
    page_size: int = 100
    has_next: bool = False
    has_prev: bool = False

    @classmethod
    def from_api_response(cls, response: dict) -> "FindingsListResponse":
        """Transform JSON:API response to simplified format."""
        data = response.get("data", [])
        links = response.get("links", {})
        meta = response.get("meta", {})

        findings = [SimplifiedFinding.from_api_response(item) for item in data]

        return cls(
            findings=findings,
            total_count=meta.get("total", len(findings)),
            page_number=meta.get("page", {}).get("number", 1),
            page_size=meta.get("page", {}).get("size", 100),
            has_next=links.get("next") is not None,
            has_prev=links.get("prev") is not None,
        )


class FindingsOverview(BaseModel):
    """Simplified findings overview with aggregate statistics."""

    total: int = 0
    fail: int = 0
    passed: int = 0  # Using 'passed' instead of 'pass' since 'pass' is a Python keyword
    muted: int = 0
    new: int = 0
    changed: int = 0
    fail_new: int = 0
    fail_changed: int = 0
    pass_new: int = 0
    pass_changed: int = 0
    muted_new: int = 0
    muted_changed: int = 0

    @classmethod
    def from_api_response(cls, response: dict) -> "FindingsOverview":
        """Transform JSON:API overview response to simplified format."""
        data = response.get("data", {})
        attributes = data.get("attributes", {})

        return cls(
            total=attributes.get("total", 0),
            fail=attributes.get("fail", 0),
            passed=attributes.get("pass", 0),
            muted=attributes.get("muted", 0),
            new=attributes.get("new", 0),
            changed=attributes.get("changed", 0),
            fail_new=attributes.get("fail_new", 0),
            fail_changed=attributes.get("fail_changed", 0),
            pass_new=attributes.get("pass_new", 0),
            pass_changed=attributes.get("pass_changed", 0),
            muted_new=attributes.get("muted_new", 0),
            muted_changed=attributes.get("muted_changed", 0),
        )
