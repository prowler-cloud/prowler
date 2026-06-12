from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ResourceNode:
    """
    Represents a single AWS resource as a node in the connectivity graph.

    id        : globally unique identifier — always the resource ARN
    type      : coarse resource type used for grouping/colour, e.g. "lambda_function"
    name      : human-readable label shown on the graph
    service   : AWS service name, e.g. "lambda", "ec2", "rds"
    region    : AWS region the resource lives in
    account_id: AWS account ID
    properties: additional resource-specific metadata (runtime, vpc_id, etc.)
    """

    id: str
    type: str
    name: str
    service: str
    region: str
    account_id: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceEdge:
    """
    Represents a directional relationship between two resource nodes.

    source_id  : ARN of the source node
    target_id  : ARN of the target node
    edge_type  : semantic type of the relationship, e.g.:
                   "network"    – resources share a network path (VPC/subnet/SG)
                   "iam"        – IAM trust or permission relationship
                   "triggers"   – one resource can invoke another (event source → Lambda)
                   "data_flow"  – data is written/read (Lambda → SQS dead-letter queue)
                   "depends_on" – soft dependency (Lambda layer, subnet belongs to VPC)
                   "routes_to"  – traffic routing (LB → target)
                   "encrypts"   – KMS key encrypts the resource
    label      : optional short label rendered on the edge in the HTML graph
    """

    source_id: str
    target_id: str
    edge_type: str
    label: Optional[str] = None


@dataclass
class ConnectivityGraph:
    """
    Container for the full inventory connectivity graph.

    nodes: all discovered resource nodes
    edges: all discovered edges between nodes
    """

    nodes: List[ResourceNode] = field(default_factory=list)
    edges: List[ResourceEdge] = field(default_factory=list)

    def add_node(self, node: ResourceNode) -> None:
        self.nodes.append(node)

    def add_edge(self, edge: ResourceEdge) -> None:
        self.edges.append(edge)

    def node_ids(self) -> set:
        return {n.id for n in self.nodes}
