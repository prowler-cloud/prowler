#!/usr/bin/env python3
"""
AWS Inventory Connectivity Graph Generator

A standalone tool that generates interactive connectivity graphs from Prowler AWS scans.
This tool reads from already-loaded AWS service clients in memory and produces:
  - JSON graph (nodes + edges)
  - Interactive HTML visualization

Usage:
    python inventory_graph.py --output-directory ./output --output-filename my-inventory

For more information, see README.md
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

# Add the contrib directory to the path so we can import the lib modules
CONTRIB_DIR = Path(__file__).parent
sys.path.insert(0, str(CONTRIB_DIR))

from lib.graph_builder import build_graph
from lib.inventory_output import write_json, write_html


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate AWS inventory connectivity graph from Prowler scan data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate graph with default settings
  python inventory_graph.py

  # Specify custom output directory and filename
  python inventory_graph.py --output-directory ./my-output --output-filename aws-inventory

  # After running a Prowler scan
  prowler aws --profile my-profile
  python inventory_graph.py --output-directory ./output

For more information, see README.md
        """,
    )

    parser.add_argument(
        "--output-directory",
        "-o",
        default="./output",
        help="Directory to save output files (default: ./output)",
    )

    parser.add_argument(
        "--output-filename",
        "-f",
        default=None,
        help="Base filename without extension (default: prowler-inventory-<timestamp>)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )

    return parser.parse_args()


def main():
    """Main entry point for the inventory graph generator."""
    args = parse_arguments()

    # Set up output paths
    output_dir = Path(args.output_directory)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate filename with timestamp if not provided
    if args.output_filename:
        base_filename = args.output_filename
    else:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        base_filename = f"prowler-inventory-{timestamp}"

    json_path = output_dir / f"{base_filename}.inventory.json"
    html_path = output_dir / f"{base_filename}.inventory.html"

    print("=" * 70)
    print("AWS Inventory Connectivity Graph Generator")
    print("=" * 70)
    print()

    # Build the graph from loaded service clients
    if args.verbose:
        print("Building connectivity graph from loaded AWS service clients...")

    graph = build_graph()

    # Check if any nodes were discovered
    if not graph.nodes:
        print("⚠️  WARNING: No nodes discovered!")
        print()
        print("This usually means:")
        print("  1. No Prowler scan has been run yet in this Python session")
        print("  2. No AWS service clients are loaded in memory")
        print()
        print("To fix this:")
        print("  1. Run a Prowler scan first: prowler aws --output-formats csv")
        print("  2. Then run this script in the same session")
        print()
        print(
            "Alternatively, integrate this tool directly into Prowler's output pipeline."
        )
        sys.exit(1)

    print(f"✓ Discovered {len(graph.nodes)} nodes and {len(graph.edges)} edges")
    print()

    # Write outputs
    if args.verbose:
        print(f"Writing JSON output to: {json_path}")
    write_json(graph, str(json_path))

    if args.verbose:
        print(f"Writing HTML output to: {html_path}")
    write_html(graph, str(html_path))

    print()
    print("=" * 70)
    print("✓ Graph generation complete!")
    print("=" * 70)
    print()
    print(f"📄 JSON: {json_path}")
    print(f"🌐 HTML: {html_path}")
    print()
    print(f"Open the HTML file in your browser to explore the interactive graph:")
    print(f"  open {html_path}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback

            traceback.print_exc()
        sys.exit(1)
