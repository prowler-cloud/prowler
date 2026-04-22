"""
inventory_output.py
-------------------
Writes the ConnectivityGraph produced by graph_builder to two files:

  <output_path>.inventory.json  – machine-readable graph (nodes + edges)
  <output_path>.inventory.html  – interactive D3.js force-directed graph
"""

import json
import os
from dataclasses import asdict
from datetime import datetime
from typing import Optional

from prowler.lib.logger import logger
from prowler.lib.outputs.inventory.models import ConnectivityGraph


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def write_json(graph: ConnectivityGraph, file_path: str) -> None:
    """Serialise the graph to a JSON file."""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        data = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "nodes": [asdict(n) for n in graph.nodes],
            "edges": [asdict(e) for e in graph.edges],
            "stats": {
                "node_count": len(graph.nodes),
                "edge_count": len(graph.edges),
            },
        }
        with open(file_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        logger.info(f"Inventory graph JSON written to {file_path}")
    except Exception as e:
        logger.error(
            f"inventory_output.write_json: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
        )


# ---------------------------------------------------------------------------
# HTML output (self-contained, D3.js CDN)
# ---------------------------------------------------------------------------

# Colour palette per node type
_NODE_COLOURS = {
    "lambda_function": "#f59e0b",
    "ec2_instance": "#3b82f6",
    "security_group": "#6366f1",
    "vpc": "#10b981",
    "subnet": "#34d399",
    "rds_instance": "#ef4444",
    "load_balancer": "#8b5cf6",
    "s3_bucket": "#06b6d4",
    "iam_role": "#f97316",
    "default": "#94a3b8",
}

# Edge stroke colours per edge type
_EDGE_COLOURS = {
    "network": "#64748b",
    "iam": "#f97316",
    "triggers": "#a855f7",
    "data_flow": "#0ea5e9",
    "depends_on": "#94a3b8",
    "routes_to": "#22c55e",
    "replicates_to": "#ec4899",
    "encrypts": "#eab308",
    "logs_to": "#78716c",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Prowler – AWS Connectivity Graph</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
    }}
    #header {{
      padding: 12px 20px;
      background: #1e293b;
      border-bottom: 1px solid #334155;
      display: flex;
      align-items: center;
      gap: 16px;
    }}
    #header h1 {{ margin: 0; font-size: 18px; font-weight: 700; }}
    #header .stats {{ font-size: 13px; color: #94a3b8; }}
    #controls {{
      padding: 8px 20px;
      background: #1e293b;
      border-bottom: 1px solid #334155;
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
    }}
    #controls label {{ font-size: 12px; color: #94a3b8; }}
    #controls select, #controls input[type=range] {{
      background: #0f172a;
      color: #e2e8f0;
      border: 1px solid #334155;
      border-radius: 4px;
      padding: 3px 6px;
      font-size: 12px;
    }}
    #graph-container {{ width: 100%; height: calc(100vh - 100px); position: relative; }}
    svg {{ width: 100%; height: 100%; }}
    .node circle {{
      stroke: #1e293b;
      stroke-width: 1.5px;
      cursor: pointer;
      transition: r 0.15s;
    }}
    .node circle:hover {{ stroke-width: 3px; }}
    .node text {{
      font-size: 10px;
      fill: #e2e8f0;
      pointer-events: none;
      text-shadow: 0 0 4px #0f172a;
    }}
    .link {{
      stroke-opacity: 0.6;
      stroke-width: 1.5px;
    }}
    .link-label {{
      font-size: 8px;
      fill: #94a3b8;
      pointer-events: none;
    }}
    #tooltip {{
      position: fixed;
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 6px;
      padding: 10px 14px;
      font-size: 12px;
      pointer-events: none;
      max-width: 320px;
      word-break: break-all;
      z-index: 9999;
      display: none;
    }}
    #tooltip strong {{ color: #f8fafc; }}
    #tooltip .prop {{ color: #94a3b8; margin-top: 4px; }}
    #legend {{
      position: absolute;
      top: 10px;
      right: 10px;
      background: rgba(30,41,59,0.9);
      border: 1px solid #334155;
      border-radius: 6px;
      padding: 10px 14px;
      font-size: 11px;
    }}
    #legend h3 {{ margin: 0 0 6px; font-size: 12px; }}
    .legend-row {{ display: flex; align-items: center; gap: 6px; margin: 3px 0; }}
    .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }}
    .legend-line {{ width: 20px; height: 2px; flex-shrink: 0; }}
  </style>
</head>
<body>
<div id="header">
  <h1>🔗 AWS Connectivity Graph</h1>
  <span class="stats" id="stat-label">Generated: {generated_at}</span>
</div>
<div id="controls">
  <label>Filter service:
    <select id="filter-service">
      <option value="">All services</option>
    </select>
  </label>
  <label>Link distance:
    <input type="range" id="link-distance" min="40" max="300" value="120"/>
  </label>
  <label>Charge strength:
    <input type="range" id="charge-strength" min="-800" max="-20" value="-250"/>
  </label>
  <span class="stats" id="visible-count"></span>
</div>
<div id="graph-container">
  <svg id="graph-svg"></svg>
  <div id="tooltip"></div>
  <div id="legend">
    <h3>Node types</h3>
    {legend_nodes_html}
    <h3 style="margin-top:8px">Edge types</h3>
    {legend_edges_html}
  </div>
</div>

<script>
const RAW_NODES = {nodes_json};
const RAW_EDGES = {edges_json};
const NODE_COLOURS = {node_colours_json};
const EDGE_COLOURS = {edge_colours_json};

// ── helpers ──────────────────────────────────────────────────────────────
function nodeColour(d) {{
  return NODE_COLOURS[d.type] || NODE_COLOURS["default"];
}}
function edgeColour(d) {{
  return EDGE_COLOURS[d.edge_type] || "#94a3b8";
}}
function nodeRadius(d) {{
  const base = {{
    lambda_function: 9, ec2_instance: 10, vpc: 14, subnet: 8,
    security_group: 7, rds_instance: 11, load_balancer: 12,
    s3_bucket: 9, iam_role: 9
  }};
  return base[d.type] || 8;
}}

// ── filter controls ───────────────────────────────────────────────────────
const services = [...new Set(RAW_NODES.map(n => n.service))].sort();
const sel = document.getElementById("filter-service");
services.forEach(s => {{
  const o = document.createElement("option");
  o.value = s; o.textContent = s;
  sel.appendChild(o);
}});

// ── D3 setup ──────────────────────────────────────────────────────────────
const svg = d3.select("#graph-svg");
const container = svg.append("g");

// zoom
svg.call(
  d3.zoom().scaleExtent([0.05, 8])
    .on("zoom", e => container.attr("transform", e.transform))
);

// arrowhead marker
const defs = svg.append("defs");
defs.append("marker")
  .attr("id", "arrow")
  .attr("viewBox", "0 -5 10 10")
  .attr("refX", 20).attr("refY", 0)
  .attr("markerWidth", 6).attr("markerHeight", 6)
  .attr("orient", "auto")
  .append("path")
    .attr("d", "M0,-5L10,0L0,5")
    .attr("fill", "#94a3b8");

// tooltip
const tooltip = document.getElementById("tooltip");

// ── simulation ────────────────────────────────────────────────────────────
let simulation, linkSel, nodeSel, labelSel;

function buildGraph(nodeFilter) {{
  // Determine which nodes to show
  const visibleNodes = nodeFilter
    ? RAW_NODES.filter(n => n.service === nodeFilter)
    : RAW_NODES;
  const visibleIds = new Set(visibleNodes.map(n => n.id));

  // Only show edges where BOTH endpoints are visible
  const visibleEdges = RAW_EDGES.filter(
    e => visibleIds.has(e.source_id) && visibleIds.has(e.target_id)
  );

  document.getElementById("visible-count").textContent =
    `Showing ${{visibleNodes.length}} nodes · ${{visibleEdges.length}} edges`;

  container.selectAll("*").remove();

  if (simulation) simulation.stop();

  const nodes = visibleNodes.map(n => ({{ ...n }}));
  const nodeIndex = Object.fromEntries(nodes.map(n => [n.id, n]));

  const links = visibleEdges.map(e => ({{
    ...e,
    source: nodeIndex[e.source_id] || e.source_id,
    target: nodeIndex[e.target_id] || e.target_id,
  }}));

  const dist = +document.getElementById("link-distance").value;
  const charge = +document.getElementById("charge-strength").value;

  simulation = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(dist))
    .force("charge", d3.forceManyBody().strength(charge))
    .force("center", d3.forceCenter(
      document.getElementById("graph-container").clientWidth / 2,
      document.getElementById("graph-container").clientHeight / 2
    ))
    .force("collision", d3.forceCollide().radius(d => nodeRadius(d) + 6));

  // Edges
  linkSel = container.append("g").attr("class", "links")
    .selectAll("line")
    .data(links)
    .join("line")
      .attr("class", "link")
      .attr("stroke", edgeColour)
      .attr("marker-end", "url(#arrow)");

  // Edge labels
  labelSel = container.append("g").attr("class", "link-labels")
    .selectAll("text")
    .data(links)
    .join("text")
      .attr("class", "link-label")
      .text(d => d.label || "");

  // Nodes
  nodeSel = container.append("g").attr("class", "nodes")
    .selectAll("g")
    .data(nodes)
    .join("g")
      .attr("class", "node")
      .call(
        d3.drag()
          .on("start", (event, d) => {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x; d.fy = d.y;
          }})
          .on("drag", (event, d) => {{ d.fx = event.x; d.fy = event.y; }})
          .on("end", (event, d) => {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null; d.fy = null;
          }})
      )
      .on("mouseover", (event, d) => {{
        const props = Object.entries(d.properties || {{}})
          .map(([k, v]) => `<div class="prop"><b>${{k}}</b>: ${{v}}</div>`)
          .join("");
        tooltip.innerHTML = `
          <strong>${{d.name}}</strong>
          <div class="prop"><b>type</b>: ${{d.type}}</div>
          <div class="prop"><b>service</b>: ${{d.service}}</div>
          <div class="prop"><b>region</b>: ${{d.region}}</div>
          <div class="prop"><b>account</b>: ${{d.account_id}}</div>
          <div class="prop" style="word-break:break-all"><b>arn</b>: ${{d.id}}</div>
          ${{props}}
        `;
        tooltip.style.display = "block";
        tooltip.style.left = (event.clientX + 12) + "px";
        tooltip.style.top  = (event.clientY - 10) + "px";
      }})
      .on("mousemove", event => {{
        tooltip.style.left = (event.clientX + 12) + "px";
        tooltip.style.top  = (event.clientY - 10) + "px";
      }})
      .on("mouseout", () => {{ tooltip.style.display = "none"; }});

  nodeSel.append("circle")
    .attr("r", nodeRadius)
    .attr("fill", nodeColour);

  nodeSel.append("text")
    .attr("dx", d => nodeRadius(d) + 3)
    .attr("dy", "0.35em")
    .text(d => d.name.length > 24 ? d.name.slice(0, 22) + "…" : d.name);

  simulation.on("tick", () => {{
    linkSel
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);

    labelSel
      .attr("x", d => (d.source.x + d.target.x) / 2)
      .attr("y", d => (d.source.y + d.target.y) / 2);

    nodeSel.attr("transform", d => `translate(${{d.x}},${{d.y}})`);
  }});
}}

// Initial render
buildGraph(null);

// Filter change
sel.addEventListener("change", () => buildGraph(sel.value || null));

// Simulation control sliders — restart on change
document.getElementById("link-distance").addEventListener("input", () => buildGraph(sel.value || null));
document.getElementById("charge-strength").addEventListener("input", () => buildGraph(sel.value || null));
</script>
</body>
</html>
"""


def _build_legend_html(colours: dict, shape: str) -> str:
    rows = []
    for key, colour in sorted(colours.items()):
        if shape == "dot":
            rows.append(
                f'<div class="legend-row">'
                f'<div class="legend-dot" style="background:{colour}"></div>'
                f'<span>{key}</span></div>'
            )
        else:
            rows.append(
                f'<div class="legend-row">'
                f'<div class="legend-line" style="background:{colour}"></div>'
                f'<span>{key}</span></div>'
            )
    return "\n".join(rows)


def write_html(graph: ConnectivityGraph, file_path: str) -> None:
    """Render the graph as a self-contained interactive HTML page."""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        nodes_json = json.dumps(
            [
                {
                    "id": n.id,
                    "type": n.type,
                    "name": n.name,
                    "service": n.service,
                    "region": n.region,
                    "account_id": n.account_id,
                    "properties": n.properties,
                }
                for n in graph.nodes
            ],
            indent=None,
            default=str,
        )
        edges_json = json.dumps(
            [
                {
                    "source_id": e.source_id,
                    "target_id": e.target_id,
                    "edge_type": e.edge_type,
                    "label": e.label or "",
                }
                for e in graph.edges
            ],
            indent=None,
            default=str,
        )

        html = _HTML_TEMPLATE.format(
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            nodes_json=nodes_json,
            edges_json=edges_json,
            node_colours_json=json.dumps(_NODE_COLOURS),
            edge_colours_json=json.dumps(_EDGE_COLOURS),
            legend_nodes_html=_build_legend_html(_NODE_COLOURS, "dot"),
            legend_edges_html=_build_legend_html(_EDGE_COLOURS, "line"),
        )

        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        logger.info(f"Inventory graph HTML written to {file_path}")
    except Exception as e:
        logger.error(
            f"inventory_output.write_html: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
        )


# ---------------------------------------------------------------------------
# Convenience entry-point called from __main__.py
# ---------------------------------------------------------------------------

def generate_inventory_outputs(output_path: str) -> None:
    """
    Build the connectivity graph from currently-loaded service clients and write
    both JSON and HTML outputs.

    Args:
        output_path: base file path WITHOUT extension, e.g.
                     "output/prowler-output-20240101120000".
                     The function appends .inventory.json and .inventory.html.
    """
    from prowler.lib.outputs.inventory.graph_builder import build_graph

    graph = build_graph()

    if not graph.nodes:
        logger.warning(
            "Inventory graph: no nodes discovered. "
            "Make sure at least one AWS service was scanned before generating the inventory."
        )

    write_json(graph, f"{output_path}.inventory.json")
    write_html(graph, f"{output_path}.inventory.html")
