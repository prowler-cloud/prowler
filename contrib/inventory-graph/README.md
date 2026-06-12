# AWS Inventory Connectivity Graph

A community-contributed tool that generates interactive connectivity graphs from Prowler AWS scans, visualizing relationships between AWS resources with zero additional API calls.

## Overview

This tool extends Prowler by producing two artifacts after a scan completes:

- **`<output>.inventory.json`** – Machine-readable graph (nodes + edges)
- **`<output>.inventory.html`** – Interactive D3.js force-directed visualization

### Why?

Prowler's existing outputs (CSV, ASFF, OCSF, HTML) report individual check findings but provide no cross-service topology view. Security engineers need to understand **how** resources are connected—which Lambda functions sit inside which VPC, which IAM roles can be assumed by which services, which event sources trigger which functions—before they can reason about attack paths, blast-radius, or lateral-movement risk.

This tool fills that gap by building a connectivity graph from the service clients that are already loaded during a Prowler scan.

## Features

### Supported AWS Services

The tool currently extracts connectivity information from:

- **Lambda** – Functions, VPC/subnet/SG edges, event source mappings, layers, DLQ, KMS
- **EC2** – Instances, security groups, subnet/VPC edges
- **VPC** – VPCs, subnets, peering connections
- **RDS** – DB instances, VPC/SG/cluster/KMS edges
- **ELBv2** – ALB/NLB load balancers, SG and VPC edges
- **S3** – Buckets, replication targets, logging buckets, KMS keys
- **IAM** – Roles, trust-relationship edges (who can assume what)

### Edge Semantic Types

Edges are typed for downstream filtering and attack-path analysis:

- `network` – Resources share a network path (VPC/subnet/SG)
- `iam` – IAM trust or permission relationship
- `triggers` – One resource can invoke another (event source → Lambda)
- `data_flow` – Data is written/read (Lambda → SQS dead-letter queue)
- `depends_on` – Soft dependency (Lambda layer, subnet belongs to VPC)
- `routes_to` – Traffic routing (LB → target)
- `replicates_to` – S3 replication
- `encrypts` – KMS key encrypts the resource
- `logs_to` – Logging relationship

### Interactive HTML Graph Features

- Force-directed layout with drag-and-drop node pinning
- Zoom / pan (mouse wheel + click-drag on background)
- Per-service color-coded nodes with a legend
- Hover tooltips showing ARN + all metadata properties
- Service filter dropdown (show only Lambda, EC2, RDS, etc.)
- Adjustable link-distance and charge-strength physics sliders
- Edge labels on every arrow

## Installation

### Prerequisites

- Python 3.9.1 or higher
- Prowler installed and configured (see [Prowler documentation](https://docs.prowler.com/))

### Setup

1. Clone or download this directory to your local machine
2. Ensure Prowler is installed and working
3. No additional dependencies required beyond Prowler's existing requirements

## Usage

### Basic Usage

Run Prowler with your desired checks, then use the inventory graph script:

```bash
# Run Prowler scan (example)
prowler aws --output-formats csv

# Generate inventory graph from the scan
python contrib/inventory-graph/inventory_graph.py --output-directory ./output
```

### Command-Line Options

```bash
python contrib/inventory-graph/inventory_graph.py [OPTIONS]

Options:
  --output-directory DIR    Directory to save output files (default: ./output)
  --output-filename NAME    Base filename without extension (default: prowler-inventory-<timestamp>)
  --help                    Show this help message and exit
```

### Example Workflow

```bash
# 1. Run a Prowler scan on your AWS account
prowler aws --profile my-aws-profile --output-formats csv html

# 2. Generate the inventory graph
python contrib/inventory-graph/inventory_graph.py \
  --output-directory ./output \
  --output-filename my-aws-inventory

# 3. Open the HTML file in your browser
open output/my-aws-inventory.inventory.html
```

### Integration with Prowler Scans

The tool reads from already-loaded AWS service clients in memory (via `sys.modules`). This means:

- **Zero extra AWS API calls** – Uses data already collected during the Prowler scan
- **Graceful degradation** – Services not scanned are silently skipped
- **Flexible** – Works with any subset of Prowler checks

## Output Files

### JSON Output (`*.inventory.json`)

Machine-readable graph structure:

```json
{
  "generated_at": "2026-03-19T12:34:56Z",
  "nodes": [
    {
      "id": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
      "type": "lambda_function",
      "name": "my-function",
      "service": "lambda",
      "region": "us-east-1",
      "account_id": "123456789012",
      "properties": {
        "runtime": "python3.9",
        "vpc_id": "vpc-abc123"
      }
    }
  ],
  "edges": [
    {
      "source_id": "arn:aws:lambda:...",
      "target_id": "arn:aws:ec2:...:vpc/vpc-abc123",
      "edge_type": "network",
      "label": "in-vpc"
    }
  ],
  "stats": {
    "node_count": 42,
    "edge_count": 87
  }
}
```

### HTML Output (`*.inventory.html`)

Self-contained interactive visualization that opens in any modern browser. No server or build step required.

## Architecture

### Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Read from sys.modules** | Zero extra AWS API calls; services not scanned are silently skipped |
| **Self-contained HTML** | D3.js v7 via CDN; no server, no build step; opens in any browser |
| **One extractor per service** | Each extractor is independently testable; adding a new service = one new file + one line in the registry |
| **Typed edges** | Semantic types allow downstream consumers (attack-path tools, Neo4j import) to filter by relationship class |

### Project Structure

```
contrib/inventory-graph/
├── README.md                    # This file
├── inventory_graph.py           # Main entry point script
├── lib/
│   ├── __init__.py
│   ├── models.py                # ResourceNode, ResourceEdge, ConnectivityGraph dataclasses
│   ├── graph_builder.py         # Reads loaded service clients from sys.modules
│   ├── inventory_output.py      # write_json(), write_html()
│   └── extractors/
│       ├── __init__.py
│       ├── lambda_extractor.py  # Lambda functions → VPC/subnet/SG/event-sources/layers/DLQ/KMS
│       ├── ec2_extractor.py     # EC2 instances + security groups → subnet/VPC
│       ├── vpc_extractor.py     # VPCs, subnets, peering connections
│       ├── rds_extractor.py     # RDS instances → VPC/SG/cluster/KMS
│       ├── elbv2_extractor.py   # ALB/NLB load balancers → SG/VPC
│       ├── s3_extractor.py      # S3 buckets → replication targets/logging buckets/KMS keys
│       └── iam_extractor.py     # IAM roles + trust-relationship edges
└── examples/
    └── sample_output.html       # Example output (optional)
```

## Testing

### Smoke Test (No AWS Credentials Needed)

```python
import sys
from unittest.mock import MagicMock

# Wire a fake Lambda client
mock_module = MagicMock()
mock_fn = MagicMock()
mock_fn.arn = "arn:aws:lambda:us-east-1:123:function:test"
mock_fn.name = "test"
mock_fn.region = "us-east-1"
mock_fn.vpc_id = "vpc-abc"
mock_fn.security_groups = ["sg-111"]
mock_fn.subnet_ids = {"subnet-aaa"}
mock_fn.environment = None
mock_fn.kms_key_arn = None
mock_fn.layers = []
mock_fn.dead_letter_config = None
mock_fn.event_source_mappings = []
mock_module.awslambda_client.functions = {mock_fn.arn: mock_fn}
mock_module.awslambda_client.audited_account = "123"
sys.modules["prowler.providers.aws.services.awslambda.awslambda_client"] = mock_module

from contrib.inventory_graph.lib.graph_builder import build_graph
from contrib.inventory_graph.lib.inventory_output import write_json, write_html

graph = build_graph()
write_json(graph, "/tmp/test.inventory.json")
write_html(graph, "/tmp/test.inventory.html")
# Open /tmp/test.inventory.html in a browser
```

## Extending

### Adding a New Service

1. Create a new extractor file in `lib/extractors/` (e.g., `dynamodb_extractor.py`)
2. Implement the `extract(client)` function that returns `(nodes, edges)`
3. Register it in `lib/graph_builder.py` in the `_SERVICE_REGISTRY` tuple

Example extractor template:

```python
from typing import List, Tuple
from prowler.lib.outputs.inventory.models import ResourceNode, ResourceEdge

def extract(client) -> Tuple[List[ResourceNode], List[ResourceEdge]]:
    """Extract DynamoDB tables and their relationships."""
    nodes = []
    edges = []
    
    for table in client.tables:
        nodes.append(
            ResourceNode(
                id=table.arn,
                type="dynamodb_table",
                name=table.name,
                service="dynamodb",
                region=table.region,
                account_id=client.audited_account,
                properties={"billing_mode": table.billing_mode}
            )
        )
        
        # Add edges for KMS encryption, streams, etc.
        if table.kms_key_arn:
            edges.append(
                ResourceEdge(
                    source_id=table.kms_key_arn,
                    target_id=table.arn,
                    edge_type="encrypts",
                    label="encrypts"
                )
            )
    
    return nodes, edges
```

## Troubleshooting

### No nodes discovered

**Problem:** The tool reports "no nodes discovered" after running.

**Solution:** Ensure you've run a Prowler scan first. The tool reads from in-memory service clients loaded during the scan. If no services were scanned, no nodes will be discovered.

### Missing services in the graph

**Problem:** Some AWS services are not appearing in the graph.

**Solution:** The tool only includes services that have been scanned by Prowler. Run Prowler with the services you want to include, or run without service filters to scan all available services.

### HTML file doesn't display properly

**Problem:** The HTML visualization doesn't load or shows errors.

**Solution:** 
- Ensure you're opening the file in a modern browser (Chrome, Firefox, Safari, Edge)
- Check your browser's console for JavaScript errors
- Verify the file was generated completely (check file size > 0)
- The HTML requires internet access to load D3.js from CDN

## Roadmap

Potential future enhancements:

- [ ] Support for additional AWS services (DynamoDB, SQS, SNS, etc.)
- [ ] Export to Neo4j / Cartography format
- [ ] Attack path analysis integration
- [ ] Multi-account/multi-region aggregation
- [ ] Custom edge type filtering in HTML UI
- [ ] Graph diff between two scans

## Contributing

This is a community contribution. If you'd like to enhance it:

1. Fork the Prowler repository
2. Make your changes in `contrib/inventory-graph/`
3. Test thoroughly
4. Submit a pull request with a clear description

## License

This tool is part of the Prowler project and is licensed under the Apache License 2.0.

## Credits

- **Author:** [@sandiyochristan](https://github.com/sandiyochristan)
- **Related PR:** [#10382](https://github.com/prowler-cloud/prowler/pull/10382)
- **Prowler Project:** [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)

## Support

For issues or questions:

- Open an issue in the [Prowler repository](https://github.com/prowler-cloud/prowler/issues)
- Join the [Prowler Community Slack](https://goto.prowler.com/slack)
- Tag your issue with `contrib:inventory-graph`
