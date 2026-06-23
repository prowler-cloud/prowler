#!/usr/bin/env python3
"""
Example: Generate AWS Inventory Graph with Mock Data

This example demonstrates how to use the inventory graph tool with mock AWS data.
No AWS credentials required.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.graph_builder import build_graph
from lib.inventory_output import write_json, write_html


def create_mock_lambda_client():
    """Create a mock Lambda client with sample data."""
    mock_module = MagicMock()

    # Create a mock Lambda function
    mock_fn = MagicMock()
    mock_fn.arn = "arn:aws:lambda:us-east-1:123456789012:function:my-test-function"
    mock_fn.name = "my-test-function"
    mock_fn.region = "us-east-1"
    mock_fn.vpc_id = "vpc-abc123"
    mock_fn.security_groups = ["sg-111222"]
    mock_fn.subnet_ids = {"subnet-aaa111", "subnet-bbb222"}
    mock_fn.environment = {"Variables": {"ENV": "production"}}
    mock_fn.kms_key_arn = (
        "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    )
    mock_fn.layers = []
    mock_fn.dead_letter_config = None
    mock_fn.event_source_mappings = []

    mock_module.awslambda_client.functions = {mock_fn.arn: mock_fn}
    mock_module.awslambda_client.audited_account = "123456789012"

    return mock_module


def create_mock_ec2_client():
    """Create a mock EC2 client with sample data."""
    mock_module = MagicMock()

    # Create a mock EC2 instance
    mock_instance = MagicMock()
    mock_instance.arn = (
        "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
    )
    mock_instance.id = "i-1234567890abcdef0"
    mock_instance.region = "us-east-1"
    mock_instance.vpc_id = "vpc-abc123"
    mock_instance.subnet_id = "subnet-aaa111"
    mock_instance.security_groups = [MagicMock(id="sg-111222")]
    mock_instance.state = "running"
    mock_instance.type = "t3.micro"
    mock_instance.tags = [{"Key": "Name", "Value": "test-instance"}]

    # Create a mock security group
    mock_sg = MagicMock()
    mock_sg.arn = "arn:aws:ec2:us-east-1:123456789012:security-group/sg-111222"
    mock_sg.id = "sg-111222"
    mock_sg.name = "test-security-group"
    mock_sg.region = "us-east-1"
    mock_sg.vpc_id = "vpc-abc123"

    mock_module.ec2_client.instances = [mock_instance]
    mock_module.ec2_client.security_groups = [mock_sg]
    mock_module.ec2_client.audited_account = "123456789012"

    return mock_module


def create_mock_vpc_client():
    """Create a mock VPC client with sample data."""
    mock_module = MagicMock()

    # Create a mock VPC
    mock_vpc = MagicMock()
    mock_vpc.arn = "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-abc123"
    mock_vpc.id = "vpc-abc123"
    mock_vpc.region = "us-east-1"
    mock_vpc.cidr_block = "10.0.0.0/16"
    mock_vpc.tags = [{"Key": "Name", "Value": "test-vpc"}]

    # Create mock subnets
    mock_subnet1 = MagicMock()
    mock_subnet1.arn = "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-aaa111"
    mock_subnet1.id = "subnet-aaa111"
    mock_subnet1.region = "us-east-1"
    mock_subnet1.vpc_id = "vpc-abc123"
    mock_subnet1.cidr_block = "10.0.1.0/24"
    mock_subnet1.availability_zone = "us-east-1a"

    mock_subnet2 = MagicMock()
    mock_subnet2.arn = "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-bbb222"
    mock_subnet2.id = "subnet-bbb222"
    mock_subnet2.region = "us-east-1"
    mock_subnet2.vpc_id = "vpc-abc123"
    mock_subnet2.cidr_block = "10.0.2.0/24"
    mock_subnet2.availability_zone = "us-east-1b"

    mock_module.vpc_client.vpcs = [mock_vpc]
    mock_module.vpc_client.subnets = [mock_subnet1, mock_subnet2]
    mock_module.vpc_client.vpc_peering_connections = []
    mock_module.vpc_client.audited_account = "123456789012"

    return mock_module


def main():
    """Main function to demonstrate the inventory graph generation."""
    print("=" * 70)
    print("AWS Inventory Graph - Mock Data Example")
    print("=" * 70)
    print()

    # Create mock clients and inject them into sys.modules
    print("Creating mock AWS service clients...")
    sys.modules["prowler.providers.aws.services.awslambda.awslambda_client"] = (
        create_mock_lambda_client()
    )
    sys.modules["prowler.providers.aws.services.ec2.ec2_client"] = (
        create_mock_ec2_client()
    )
    sys.modules["prowler.providers.aws.services.vpc.vpc_client"] = (
        create_mock_vpc_client()
    )
    print("✓ Mock clients created")
    print()

    # Build the graph
    print("Building connectivity graph...")
    graph = build_graph()
    print(f"✓ Graph built: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    print()

    # Display discovered nodes
    print("Discovered nodes:")
    for node in graph.nodes:
        print(f"  - {node.type}: {node.name} ({node.region})")
    print()

    # Display discovered edges
    print("Discovered edges:")
    for edge in graph.edges:
        source_node = next((n for n in graph.nodes if n.id == edge.source_id), None)
        target_node = next((n for n in graph.nodes if n.id == edge.target_id), None)
        source_name = source_node.name if source_node else edge.source_id
        target_name = target_node.name if target_node else edge.target_id
        print(f"  - {source_name} --[{edge.edge_type}]--> {target_name}")
    print()

    # Write outputs
    output_dir = Path(__file__).parent
    json_path = output_dir / "example_output.inventory.json"
    html_path = output_dir / "example_output.inventory.html"

    print("Writing output files...")
    write_json(graph, str(json_path))
    write_html(graph, str(html_path))
    print(f"✓ JSON written to: {json_path}")
    print(f"✓ HTML written to: {html_path}")
    print()

    print("=" * 70)
    print("✓ Example complete!")
    print("=" * 70)
    print()
    print(f"Open the HTML file to view the interactive graph:")
    print(f"  open {html_path}")
    print()


if __name__ == "__main__":
    main()
