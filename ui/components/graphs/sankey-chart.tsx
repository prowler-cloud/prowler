"use client";

import { useState } from "react";
import { Rectangle, ResponsiveContainer, Sankey, Tooltip } from "recharts";

import { CHART_COLORS } from "./shared/constants";
import { ChartTooltip } from "./shared/chart-tooltip";

interface SankeyNode {
  name: string;
  newFindings?: number;
  change?: number;
}

interface SankeyLink {
  source: number;
  target: number;
  value: number;
}

interface SankeyChartProps {
  data: {
    nodes: SankeyNode[];
    links: SankeyLink[];
  };
  height?: number;
}

interface LinkTooltipState {
  show: boolean;
  x: number;
  y: number;
  sourceName: string;
  targetName: string;
  value: number;
  color: string;
}

interface NodeTooltipState {
  show: boolean;
  x: number;
  y: number;
  name: string;
  value: number;
  color: string;
  newFindings?: number;
  change?: number;
}

// Note: Using hex colors directly because Recharts SVG fill doesn't resolve CSS variables
const COLORS: Record<string, string> = {
  Success: "#86da26",
  Fail: "#db2b49",
  AWS: "#ff9900",
  Azure: "#00bcd4",
  Google: "#EA4335",
  Critical: "#971348",
  High: "#ff3077",
  Medium: "#ff7d19",
  Low: "#fdd34f",
  Info: "#2e51b2",
  Informational: "#2e51b2",
};

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div
        className="rounded-lg border p-3 shadow-lg"
        style={{
          borderColor: CHART_COLORS.tooltipBorder,
          backgroundColor: CHART_COLORS.tooltipBackground,
        }}
      >
        <p
          className="text-sm font-semibold"
          style={{ color: CHART_COLORS.textPrimary }}
        >
          {data.name}
        </p>
        {data.value && (
          <p className="text-xs" style={{ color: CHART_COLORS.textSecondary }}>
            Value: {data.value}
          </p>
        )}
      </div>
    );
  }
  return null;
};

const CustomNode = (props: any) => {
  const { x, y, width, height, payload, containerWidth } = props;
  const isOut = x + width + 6 > containerWidth;
  const nodeName = payload.name;
  const color = COLORS[nodeName] || CHART_COLORS.defaultColor;
  const isHidden = nodeName === "";
  const hasTooltip = !isHidden && payload.newFindings;

  const handleMouseEnter = (e: React.MouseEvent) => {
    if (!hasTooltip) return;

    const rect = e.currentTarget.closest("svg") as SVGSVGElement;
    if (rect) {
      const bbox = rect.getBoundingClientRect();
      props.onNodeHover?.({
        x: e.clientX - bbox.left,
        y: e.clientY - bbox.top,
        name: nodeName,
        value: payload.value,
        color,
        newFindings: payload.newFindings,
        change: payload.change,
      });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!hasTooltip) return;

    const rect = e.currentTarget.closest("svg") as SVGSVGElement;
    if (rect) {
      const bbox = rect.getBoundingClientRect();
      props.onNodeMove?.({
        x: e.clientX - bbox.left,
        y: e.clientY - bbox.top,
      });
    }
  };

  const handleMouseLeave = () => {
    if (!hasTooltip) return;
    props.onNodeLeave?.();
  };

  return (
    <g
      style={{ cursor: hasTooltip ? "pointer" : "default" }}
      onMouseEnter={handleMouseEnter}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
    >
      <Rectangle
        x={x}
        y={y}
        width={width}
        height={height}
        fill={color}
        fillOpacity={isHidden ? "0" : "1"}
      />
      {!isHidden && (
        <>
          <text
            textAnchor={isOut ? "end" : "start"}
            x={isOut ? x - 6 : x + width + 6}
            y={y + height / 2}
            fontSize="14"
            fill={CHART_COLORS.textPrimary}
          >
            {nodeName}
          </text>
          <text
            textAnchor={isOut ? "end" : "start"}
            x={isOut ? x - 6 : x + width + 6}
            y={y + height / 2 + 13}
            fontSize="12"
            fill={CHART_COLORS.textSecondary}
          >
            {payload.value}
          </text>
        </>
      )}
    </g>
  );
};

const CustomLink = (props: any) => {
  const {
    sourceX,
    targetX,
    sourceY,
    targetY,
    sourceControlX,
    targetControlX,
    linkWidth,
    index,
  } = props;

  const sourceName = props.payload.source?.name || "";
  const targetName = props.payload.target?.name || "";
  const value = props.payload.value || 0;
  const color = COLORS[sourceName] || CHART_COLORS.defaultColor;
  const isHidden = targetName === "";

  const isHovered =
    props.hoveredLink !== null && props.hoveredLink === index;
  const hasHoveredLink = props.hoveredLink !== null;

  const pathD = `
    M${sourceX},${sourceY + linkWidth / 2}
    C${sourceControlX},${sourceY + linkWidth / 2}
      ${targetControlX},${targetY + linkWidth / 2}
      ${targetX},${targetY + linkWidth / 2}
    L${targetX},${targetY - linkWidth / 2}
    C${targetControlX},${targetY - linkWidth / 2}
      ${sourceControlX},${sourceY - linkWidth / 2}
      ${sourceX},${sourceY - linkWidth / 2}
    Z
  `;

  const getOpacity = () => {
    if (isHidden) return "0";
    if (!hasHoveredLink) return "0.4";
    return isHovered ? "0.8" : "0.1";
  };

  const handleMouseEnter = (e: React.MouseEvent) => {
    const rect = e.currentTarget.parentElement?.parentElement
      ?.parentElement as unknown as SVGSVGElement;
    if (rect) {
      const bbox = rect.getBoundingClientRect();
      props.onLinkHover?.(index, {
        x: e.clientX - bbox.left,
        y: e.clientY - bbox.top,
        sourceName,
        targetName,
        value,
        color,
      });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    const rect = e.currentTarget.parentElement?.parentElement
      ?.parentElement as unknown as SVGSVGElement;
    if (rect && isHovered) {
      const bbox = rect.getBoundingClientRect();
      props.onLinkMove?.({
        x: e.clientX - bbox.left,
        y: e.clientY - bbox.top,
      });
    }
  };

  const handleMouseLeave = () => {
    props.onLinkLeave?.();
  };

  return (
    <g>
      <path
        d={pathD}
        fill={color}
        fillOpacity={getOpacity()}
        stroke="none"
        style={{ cursor: "pointer", transition: "fill-opacity 0.2s" }}
        onMouseEnter={handleMouseEnter}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
      />
    </g>
  );
};

export function SankeyChart({ data, height = 400 }: SankeyChartProps) {
  const [hoveredLink, setHoveredLink] = useState<number | null>(null);
  const [linkTooltip, setLinkTooltip] = useState<LinkTooltipState>({
    show: false,
    x: 0,
    y: 0,
    sourceName: "",
    targetName: "",
    value: 0,
    color: "",
  });

  const [nodeTooltip, setNodeTooltip] = useState<NodeTooltipState>({
    show: false,
    x: 0,
    y: 0,
    name: "",
    value: 0,
    color: "",
  });

  const handleLinkHover = (
    index: number,
    data: Omit<LinkTooltipState, "show">,
  ) => {
    setHoveredLink(index);
    setLinkTooltip({ show: true, ...data });
  };

  const handleLinkMove = (position: { x: number; y: number }) => {
    setLinkTooltip((prev) => ({
      ...prev,
      x: position.x,
      y: position.y,
    }));
  };

  const handleLinkLeave = () => {
    setHoveredLink(null);
    setLinkTooltip((prev) => ({ ...prev, show: false }));
  };

  const handleNodeHover = (data: Omit<NodeTooltipState, "show">) => {
    setNodeTooltip({ show: true, ...data });
  };

  const handleNodeMove = (position: { x: number; y: number }) => {
    setNodeTooltip((prev) => ({
      ...prev,
      x: position.x,
      y: position.y,
    }));
  };

  const handleNodeLeave = () => {
    setNodeTooltip((prev) => ({ ...prev, show: false }));
  };

  return (
    <div className="relative">
      <ResponsiveContainer width="100%" height={height}>
        <Sankey
          data={data}
          node={
            <CustomNode
              onNodeHover={handleNodeHover}
              onNodeMove={handleNodeMove}
              onNodeLeave={handleNodeLeave}
            />
          }
          link={
            <CustomLink
              hoveredLink={hoveredLink}
              onLinkHover={handleLinkHover}
              onLinkMove={handleLinkMove}
              onLinkLeave={handleLinkLeave}
            />
          }
          nodePadding={50}
          margin={{ top: 20, right: 160, bottom: 20, left: 160 }}
          sort={false}
        >
          <Tooltip content={<CustomTooltip />} />
        </Sankey>
      </ResponsiveContainer>
      {linkTooltip.show && (
        <div
          className="pointer-events-none absolute z-50"
          style={{
            left: `${Math.max(125, Math.min(linkTooltip.x, window.innerWidth - 125))}px`,
            top: `${Math.max(linkTooltip.y - 80, 10)}px`,
            transform: "translate(-50%, -100%)",
          }}
        >
          <ChartTooltip
            active={true}
            payload={[
              {
                payload: {
                  name: linkTooltip.targetName,
                  value: linkTooltip.value,
                  color: linkTooltip.color,
                },
                color: linkTooltip.color,
              },
            ]}
            label={`${linkTooltip.sourceName} → ${linkTooltip.targetName}`}
          />
        </div>
      )}
      {nodeTooltip.show && (
        <div
          className="pointer-events-none absolute z-50"
          style={{
            left: `${Math.max(125, Math.min(nodeTooltip.x, window.innerWidth - 125))}px`,
            top: `${Math.max(nodeTooltip.y - 80, 10)}px`,
            transform: "translate(-50%, -100%)",
          }}
        >
          <ChartTooltip
            active={true}
            payload={[
              {
                payload: {
                  name: nodeTooltip.name,
                  value: nodeTooltip.value,
                  color: nodeTooltip.color,
                  newFindings: nodeTooltip.newFindings,
                  change: nodeTooltip.change,
                },
                color: nodeTooltip.color,
              },
            ]}
          />
        </div>
      )}
    </div>
  );
}
