"""Data models for Attack Paths scans and queries.

This module provides Pydantic models for representing Attack Paths data
with two-tier complexity:
- AttackPathScan: For list operations with essential fields
- AttackPathQuery: Query definition with parameters
- AttackPathQueryResult: Graph result with nodes, relationships, and summary

All models inherit from MinimalSerializerMixin to exclude None/empty values
for optimal LLM token usage.
"""

from typing import Any, Literal

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from pydantic import BaseModel, ConfigDict, Field


class AttackPathScan(MinimalSerializerMixin, BaseModel):
    """Simplified attack paths scan representation for list operations.

    Includes core fields for efficient overview.
    Used by list_attack_paths_scans() tool.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Unique UUIDv4 identifier for this attack paths scan")
    state: Literal[
        "available", "scheduled", "executing", "completed", "failed", "cancelled"
    ] = Field(
        description="Current state of the scan: available, scheduled, executing, completed, failed, or cancelled"
    )
    progress: int = Field(
        default=0, description="Scan completion progress as percentage (0-100)"
    )
    provider_id: str = Field(
        description="UUIDv4 identifier of the provider this scan is associated with"
    )
    provider_alias: str | None = Field(
        default=None,
        description="Human-friendly alias for the provider",
    )
    provider_type: str | None = Field(
        default=None,
        description="Cloud provider type (aws, azure, gcp, etc.)",
    )
    provider_uid: str | None = Field(
        default=None,
        description="Provider's external identifier (e.g., AWS Account ID)",
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "AttackPathScan":
        """Transform JSON:API attack paths scan response to simplified model.

        Args:
            data: Scan data from API response['data'] (single item or list item)

        Returns:
            AttackPathScan instance
        """
        attributes = data["attributes"]
        relationships = data.get("relationships", {})

        provider_id = relationships.get("provider", {}).get("data", {}).get("id")

        return cls(
            id=data["id"],
            state=attributes["state"],
            progress=attributes.get("progress", 0),
            provider_id=provider_id,
            provider_alias=attributes.get("provider_alias"),
            provider_type=attributes.get("provider_type"),
            provider_uid=attributes.get("provider_uid"),
        )


class AttackPathScansListResponse(BaseModel):
    """Response model for list_attack_paths_scans() with pagination metadata.

    Follows established pattern from ScansListResponse.
    """

    scans: list[AttackPathScan]
    total_num_scans: int
    total_num_pages: int
    current_page: int

    @classmethod
    def from_api_response(
        cls, response: dict[str, Any]
    ) -> "AttackPathScansListResponse":
        """Transform JSON:API list response to scans list with pagination.

        Args:
            response: Full API response with data and meta

        Returns:
            AttackPathScansListResponse with simplified scans and pagination metadata
        """
        pagination = response.get("meta", {}).get("pagination", None)

        if pagination is None:
            raise ValueError("Missing pagination metadata in API response")
        else:
            # Transform each scan
            scans = [
                AttackPathScan.from_api_response(item)
                for item in response.get("data", [])
            ]

            return cls(
                scans=scans,
                total_num_scans=pagination.get("count"),
                total_num_pages=pagination.get("pages"),
                current_page=pagination.get("page"),
            )


class AttackPathQueryParameter(MinimalSerializerMixin, BaseModel):
    """Parameter definition for an attack paths query.

    Describes a parameter that must be provided when running a query.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Parameter name used in the query")
    label: str = Field(description="Human-readable label for the parameter")
    data_type: str = Field(
        default="string", description="Data type of the parameter (e.g., 'string')"
    )
    description: str | None = Field(
        default=None, description="Detailed description of what the parameter is for"
    )
    placeholder: str | None = Field(
        default=None, description="Example value for the parameter"
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "AttackPathQueryParameter":
        """Transform parameter data to model.

        Args:
            data: Parameter data from API response

        Returns:
            AttackPathQueryParameter instance
        """
        return cls(
            name=data["name"],
            label=data["label"],
            data_type=data.get("data_type", "string"),
            description=data.get("description"),
            placeholder=data.get("placeholder"),
        )


class AttackPathQuery(MinimalSerializerMixin, BaseModel):
    """Attack paths query definition.

    Describes a query that can be executed against the attack paths graph.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Unique identifier for the query")
    name: str = Field(description="Human-readable name for the query")
    description: str = Field(description="Detailed description of what the query finds")
    provider: str = Field(description="Cloud provider type this query applies to")
    parameters: list[AttackPathQueryParameter] = Field(
        default_factory=list, description="Parameters required to execute the query"
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "AttackPathQuery":
        """Transform query data to model.

        Handles JSON:API format where fields are nested under 'attributes'.

        Args:
            data: Query data from API response (JSON:API format)

        Returns:
            AttackPathQuery instance
        """
        # JSON:API format has attributes nested
        attributes = data.get("attributes", {})

        parameters = [
            AttackPathQueryParameter.from_api_response(p)
            for p in attributes.get("parameters", [])
        ]

        return cls(
            id=data["id"],
            name=attributes["name"],
            description=attributes["description"],
            provider=attributes["provider"],
            parameters=parameters,
        )


class AttackPathsGraphNode(MinimalSerializerMixin, BaseModel):
    """A node in the attack paths graph.

    Represents a cloud resource, finding, or virtual node in the graph.
    """

    model_config = ConfigDict(frozen=True)

    resource_id: str = Field(description="ID of the resource represented by this node")
    labels: list[str] = Field(
        description="Node labels (e.g., 'EC2Instance', 'S3Bucket', 'ProwlerFinding')"
    )
    properties: dict[str, Any] = Field(
        default_factory=dict, description="Node properties"
    )
    # Extracted security-relevant fields for easier access
    severity: str | None = Field(
        default=None, description="Severity level for ProwlerFinding nodes"
    )
    status: str | None = Field(
        default=None, description="Status for ProwlerFinding nodes (FAIL/PASS)"
    )
    status_extended: str | None = Field(
        default=None, description="Extended status for ProwlerFinding nodes"
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "AttackPathsGraphNode":
        """Transform node data to model.

        Args:
            data: Node data from API response

        Returns:
            AttackPathsGraphNode instance with extracted fields
        """
        properties = data.get("properties", {})
        labels = data.get("labels", [])

        # Extract security-relevant fields from properties
        if "ProwlerFinding" in labels:
            severity = properties.get("severity", None)
            status = properties.get("status", None)
            status_extended = properties.get("status_extended", None)
        else:
            severity = None
            status = None
            status_extended = None

        return cls(
            resource_id=properties.get("id", ""),
            labels=labels,
            properties=properties,
            severity=severity,
            status=status,
            status_extended=status_extended,
        )


class AttackPathsGraphRelationship(MinimalSerializerMixin, BaseModel):
    """A relationship (edge) in the attack paths graph.

    Represents a connection between two nodes.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Unique identifier for the relationship")
    label: str = Field(
        description="Relationship type (e.g., 'CAN_ACCESS', 'STS_ASSUMEROLE_ALLOW')"
    )
    source: str = Field(description="ID of the source node")
    target: str = Field(description="ID of the target node")

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "AttackPathsGraphRelationship":
        """Transform relationship data to model.

        Args:
            data: Relationship data from API response

        Returns:
            AttackPathsGraphRelationship instance
        """
        return cls(
            id=data["id"],
            label=data["label"],
            source=data["source"],
            target=data["target"],
        )


class AttackPathQueryResult(MinimalSerializerMixin, BaseModel):
    """Result of executing an attack paths query.

    Contains the graph data (nodes and relationships) plus a summary.
    """

    model_config = ConfigDict(frozen=True)

    nodes: list[AttackPathsGraphNode] = Field(
        default_factory=list, description="Nodes in the attack path graph"
    )
    relationships: list[AttackPathsGraphRelationship] = Field(
        default_factory=list, description="Relationships connecting the nodes"
    )

    @classmethod
    def from_api_response(
        cls,
        response: dict[str, Any],
    ) -> "AttackPathQueryResult":
        """Transform API response to query result.

        Args:
            response: API response with nodes and relationships

        Returns:
            AttackPathQueryResult with parsed data and summary
        """
        attributes = response.get("data", {}).get("attributes")
        nodes_data = attributes.get("nodes", [])
        relationships_data = attributes.get("relationships", [])

        nodes = [AttackPathsGraphNode.from_api_response(n) for n in nodes_data]
        relationships = [
            AttackPathsGraphRelationship.from_api_response(r)
            for r in relationships_data
        ]

        return cls(
            nodes=nodes,
            relationships=relationships,
        )
