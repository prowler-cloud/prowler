"use client";

import { useEffect, useState } from "react";
import { Rectangle, ResponsiveContainer, Sankey, Tooltip } from "recharts";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  IacProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  OracleCloudProviderBadge,
} from "@/components/icons/providers-badge";
import { IconSvgProps } from "@/types";

import { ChartTooltip } from "./shared/chart-tooltip";

// Map node names to their corresponding provider icon components
const PROVIDER_ICONS: Record<string, React.FC<IconSvgProps>> = {
  AWS: AWSProviderBadge,
  Azure: AzureProviderBadge,
  "Google Cloud": GCPProviderBadge,
  Kubernetes: KS8ProviderBadge,
  "Microsoft 365": M365ProviderBadge,
  GitHub: GitHubProviderBadge,
  "Infrastructure as Code": IacProviderBadge,
  "Oracle Cloud Infrastructure": OracleCloudProviderBadge,
};

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

const TOOLTIP_OFFSET_PX = 10;
const MIN_LINK_WIDTH = 4;

// Map color names to CSS variable names defined in globals.css
const COLOR_MAP: Record<string, string> = {
  // Status colors
  Success: "--color-bg-pass",
  Pass: "--color-bg-pass",
  Fail: "--color-bg-fail",
  // Provider colors
  AWS: "--color-bg-data-aws",
  Azure: "--color-bg-data-azure",
  "Google Cloud": "--color-bg-data-gcp",
  Kubernetes: "--color-bg-data-kubernetes",
  "Microsoft 365": "--color-bg-data-m365",
  GitHub: "--color-bg-data-github",
  "Infrastructure as Code": "--color-bg-data-muted",
  "Oracle Cloud Infrastructure": "--color-bg-data-muted",
  // Severity colors
  Critical: "--color-bg-data-critical",
  High: "--color-bg-data-high",
  Medium: "--color-bg-data-medium",
  Low: "--color-bg-data-low",
  Info: "--color-bg-data-info",
  Informational: "--color-bg-data-info",
};

/**
 * Compute color value from CSS variable name at runtime.
 * SVG fill attributes cannot directly resolve CSS variables,
 * so we extract computed values from globals.css CSS variables.
 * Falls back to black (#000000) if variable not found or access fails.
 *
 * @param colorName - Key in COLOR_MAP (e.g., "AWS", "Fail")
 * @returns Computed CSS variable value or fallback color
 */
const getColorVariable = (colorName: string): string => {
  const varName = COLOR_MAP[colorName];
  if (!varName) return "#000000";

  try {
    if (typeof document === "undefined") {
      // SSR context - return fallback
      return "#000000";
    }
    return (
      getComputedStyle(document.documentElement)
        .getPropertyValue(varName)
        .trim() || "#000000"
    );
  } catch (error: unknown) {
    // CSS variables not loaded or access failed - return fallback
    return "#000000";
  }
};

// Initialize all color variables from CSS
const initializeColors = (): Record<string, string> => {
  const colors: Record<string, string> = {};
  for (const [colorName] of Object.entries(COLOR_MAP)) {
    colors[colorName] = getColorVariable(colorName);
  }
  return colors;
};

interface TooltipPayload {
  payload: {
    source?: { name: string };
    target?: { name: string };
    value?: number;
    name?: string;
  };
}

interface TooltipProps {
  active?: boolean;
  payload?: TooltipPayload[];
}

interface CustomNodeProps {
  x: number;
  y: number;
  width: number;
  height: number;
  payload: SankeyNode & {
    value: number;
    newFindings?: number;
    change?: number;
  };
  containerWidth: number;
  colors: Record<string, string>;
  onNodeHover?: (data: Omit<NodeTooltipState, "show">) => void;
  onNodeMove?: (position: { x: number; y: number }) => void;
  onNodeLeave?: () => void;
}

interface CustomLinkProps {
  sourceX: number;
  targetX: number;
  sourceY: number;
  targetY: number;
  sourceControlX: number;
  targetControlX: number;
  linkWidth: number;
  index: number;
  payload: {
    source?: { name: string };
    target?: { name: string };
    value?: number;
  };
  hoveredLink: number | null;
  colors: Record<string, string>;
  onLinkHover?: (index: number, data: Omit<LinkTooltipState, "show">) => void;
  onLinkMove?: (position: { x: number; y: number }) => void;
  onLinkLeave?: () => void;
}

const CustomTooltip = ({ active, payload }: TooltipProps) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    const sourceName = data.source?.name || data.name;
    const targetName = data.target?.name;
    const value = data.value;

    return (
      <div className="chart-tooltip">
        <p className="chart-tooltip-title">
          {sourceName}
          {targetName ? ` → ${targetName}` : ""}
        </p>
        {value && <p className="chart-tooltip-subtitle">{value}</p>}
      </div>
    );
  }
  return null;
};

const CustomNode = ({
  x,
  y,
  width,
  height,
  payload,
  containerWidth,
  colors,
  onNodeHover,
  onNodeMove,
  onNodeLeave,
}: CustomNodeProps) => {
  const isOut = x + width + 6 > containerWidth;
  const nodeName = payload.name;
  const color = colors[nodeName] || "var(--color-text-neutral-tertiary)";
  const isHidden = nodeName === "";
  const hasTooltip = !isHidden && payload.newFindings;

  const handleMouseEnter = (e: React.MouseEvent) => {
    if (!hasTooltip) return;

    const rect = e.currentTarget.closest("svg") as SVGSVGElement;
    if (rect) {
      const bbox = rect.getBoundingClientRect();
      onNodeHover?.({
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
      onNodeMove?.({
        x: e.clientX - bbox.left,
        y: e.clientY - bbox.top,
      });
    }
  };

  const handleMouseLeave = () => {
    if (!hasTooltip) return;
    onNodeLeave?.();
  };

  const IconComponent = PROVIDER_ICONS[nodeName];
  const hasIcon = IconComponent !== undefined;
  const iconSize = 24;
  const iconGap = 8;

  // Calculate text position accounting for icon
  const textOffsetX = isOut ? x - 6 : x + width + 6;
  const iconOffsetX = isOut
    ? textOffsetX - iconSize - iconGap
    : textOffsetX + iconGap;

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
          {hasIcon && (
            <foreignObject
              x={isOut ? iconOffsetX : textOffsetX}
              y={y + height / 2 - iconSize / 2 - 2}
              width={iconSize}
              height={iconSize}
            >
              <div className="flex items-center justify-center">
                <IconComponent width={iconSize} height={iconSize} />
              </div>
            </foreignObject>
          )}
          <text
            textAnchor={isOut ? "end" : "start"}
            x={
              hasIcon
                ? isOut
                  ? iconOffsetX - iconGap
                  : textOffsetX + iconSize + iconGap * 2
                : textOffsetX
            }
            y={y + height / 2}
            fontSize="14"
            fill="var(--color-text-neutral-primary)"
          >
            {nodeName}
          </text>
          <text
            textAnchor={isOut ? "end" : "start"}
            x={
              hasIcon
                ? isOut
                  ? iconOffsetX - iconGap
                  : textOffsetX + iconSize + iconGap * 2
                : textOffsetX
            }
            y={y + height / 2 + 13}
            fontSize="12"
            fill="var(--color-text-neutral-secondary)"
          >
            {payload.value}
          </text>
        </>
      )}
    </g>
  );
};

const CustomLink = ({
  sourceX,
  targetX,
  sourceY,
  targetY,
  sourceControlX,
  targetControlX,
  linkWidth,
  index,
  payload,
  hoveredLink,
  colors,
  onLinkHover,
  onLinkMove,
  onLinkLeave,
}: CustomLinkProps) => {
  const sourceName = payload.source?.name || "";
  const targetName = payload.target?.name || "";
  const value = payload.value || 0;
  const color = colors[sourceName] || "var(--color-text-neutral-tertiary)";
  const isHidden = targetName === "";

  const isHovered = hoveredLink !== null && hoveredLink === index;
  const hasHoveredLink = hoveredLink !== null;

  // Ensure minimum link width for better visibility of small values
  const effectiveLinkWidth = Math.max(linkWidth, MIN_LINK_WIDTH);

  const pathD = `
    M${sourceX},${sourceY + effectiveLinkWidth / 2}
    C${sourceControlX},${sourceY + effectiveLinkWidth / 2}
      ${targetControlX},${targetY + effectiveLinkWidth / 2}
      ${targetX},${targetY + effectiveLinkWidth / 2}
    L${targetX},${targetY - effectiveLinkWidth / 2}
    C${targetControlX},${targetY - effectiveLinkWidth / 2}
      ${sourceControlX},${sourceY - effectiveLinkWidth / 2}
      ${sourceX},${sourceY - effectiveLinkWidth / 2}
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
      onLinkHover?.(index, {
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
      onLinkMove?.({
        x: e.clientX - bbox.left,
        y: e.clientY - bbox.top,
      });
    }
  };

  const handleMouseLeave = () => {
    onLinkLeave?.();
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
  const [colors, setColors] = useState<Record<string, string>>({});
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

  // Initialize colors from CSS variables on mount
  useEffect(() => {
    setColors(initializeColors());
  }, []);

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

  // Create callback references that wrap custom props and Recharts-injected props
  const wrappedCustomNode = (
    props: Omit<
      CustomNodeProps,
      "colors" | "onNodeHover" | "onNodeMove" | "onNodeLeave"
    >,
  ) => (
    <CustomNode
      {...props}
      colors={colors}
      onNodeHover={handleNodeHover}
      onNodeMove={handleNodeMove}
      onNodeLeave={handleNodeLeave}
    />
  );

  const wrappedCustomLink = (
    props: Omit<
      CustomLinkProps,
      "colors" | "hoveredLink" | "onLinkHover" | "onLinkMove" | "onLinkLeave"
    >,
  ) => (
    <CustomLink
      {...props}
      colors={colors}
      hoveredLink={hoveredLink}
      onLinkHover={handleLinkHover}
      onLinkMove={handleLinkMove}
      onLinkLeave={handleLinkLeave}
    />
  );

  return (
    <div className="relative">
      <ResponsiveContainer width="100%" height={height}>
        <Sankey
          data={data}
          node={wrappedCustomNode}
          link={wrappedCustomLink}
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
            left: `${Math.max(TOOLTIP_OFFSET_PX, linkTooltip.x)}px`,
            top: `${Math.max(TOOLTIP_OFFSET_PX, linkTooltip.y)}px`,
            transform: `translate(${TOOLTIP_OFFSET_PX}px, -100%)`,
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
            left: `${Math.max(TOOLTIP_OFFSET_PX, nodeTooltip.x)}px`,
            top: `${Math.max(TOOLTIP_OFFSET_PX, nodeTooltip.y)}px`,
            transform: `translate(${TOOLTIP_OFFSET_PX}px, -100%)`,
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
