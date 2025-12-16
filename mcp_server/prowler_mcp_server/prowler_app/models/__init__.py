"""Pydantic models for Prowler App MCP Server."""

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from prowler_mcp_server.prowler_app.models.findings import (
    CheckMetadata,
    CheckRemediation,
    DetailedFinding,
    FindingsListResponse,
    FindingsOverview,
    SimplifiedFinding,
)
from prowler_mcp_server.prowler_app.models.muting import (
    DetailedMuteRule,
    MutelistResponse,
    MuteRulesListResponse,
    SimplifiedMuteRule,
)

__all__ = [
    # Base models
    "MinimalSerializerMixin",
    # Findings models
    "CheckMetadata",
    "CheckRemediation",
    "DetailedFinding",
    "FindingsListResponse",
    "FindingsOverview",
    "SimplifiedFinding",
    # Muting models
    "DetailedMuteRule",
    "MutelistResponse",
    "MuteRulesListResponse",
    "SimplifiedMuteRule",
]
