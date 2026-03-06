"use client";

import { Info } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { Rectangle, ResponsiveContainer, Sankey, Tooltip } from "recharts";

import { PROVIDER_ICONS } from "@/components/icons/providers-badge";
import { initializeChartColors } from "@/lib/charts/colors";
import { PROVIDER_DISPLAY_NAMES } from "@/types/providers";
import { SEVERITY_FILTER_MAP } from "@/types/severities";

import { ChartTooltip } from "./shared/chart-tooltip";

// Reverse mapping from display name to provider type for URL filters
const PROVIDER_TYPE_MAP: Record<string, string> = Object.entries(
  PROVIDER_DISPLAY_NAMES,
).reduce(
  (acc, [type, displayName]) => {
    acc[displayName] = type;
    return acc;
  },
  {} as Record<string, string>,
);

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

interface ZeroDataProvider {
  id: string;
  displayName: string;
}

interface SankeyChartProps {
  data: {
    nodes: SankeyNode[];
    links: SankeyLink[];
  };
  zeroDataProviders?: ZeroDataProvider[];
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
  onNodeClick?: (nodeName: string) => void;
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
  onLinkClick?: (sourceName: string, targetName: string) => void;
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
  onNodeClick,
}: CustomNodeProps) => {
  const isOut = x + width + 6 > containerWidth;
  const nodeName = payload.name;
  const color = colors[nodeName] || "var(--color-text-neutral-tertiary)";
  const isHidden = nodeName === "";
  const hasTooltip = !isHidden && payload.newFindings;
  const isClickable = SEVERITY_FILTER_MAP[nodeName] !== undefined;

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

  const handleClick = () => {
    if (isClickable) {
      onNodeClick?.(nodeName);
    }
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
      style={{ cursor: isClickable || hasTooltip ? "pointer" : "default" }}
      onMouseEnter={handleMouseEnter}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      onClick={handleClick}
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
  onLinkClick,
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

  const handleClick = () => {
    if (!isHidden && onLinkClick) {
      onLinkClick(sourceName, targetName);
    }
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
        onClick={handleClick}
      />
    </g>
  );
};

export function SankeyChart({
  data,
  zeroDataProviders = [],
  height = 400,
}: SankeyChartProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
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
    setColors(initializeChartColors());
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

  const handleNodeClick = (nodeName: string) => {
    const severityFilter = SEVERITY_FILTER_MAP[nodeName];
    if (severityFilter) {
      const params = new URLSearchParams(searchParams.toString());
      params.set("filter[severity__in]", severityFilter);
      params.set("filter[status__in]", "FAIL");
      params.set("filter[muted]", "false");
      router.push(`/findings?${params.toString()}`);
    }
  };

  const handleLinkClick = (sourceName: string, targetName: string) => {
    const providerType = PROVIDER_TYPE_MAP[sourceName];
    const severityFilter = SEVERITY_FILTER_MAP[targetName];

    if (severityFilter) {
      const params = new URLSearchParams(searchParams.toString());

      // Always set provider_type filter based on the clicked link's source (provider)
      // This ensures clicking "AWS → High" filters by AWS even when no global filter is set
      const hasProviderFilter = searchParams.has("filter[provider_id__in]");
      if (providerType && !hasProviderFilter) {
        params.set("filter[provider_type__in]", providerType);
      }

      params.set("filter[severity__in]", severityFilter);
      params.set("filter[status__in]", "FAIL");
      params.set("filter[muted]", "false");
      router.push(`/findings?${params.toString()}`);
    }
  };

  // Create callback references that wrap custom props and Recharts-injected props
  const wrappedCustomNode = (
    props: Omit<
      CustomNodeProps,
      "colors" | "onNodeHover" | "onNodeMove" | "onNodeLeave" | "onNodeClick"
    >,
  ) => (
    <CustomNode
      {...props}
      colors={colors}
      onNodeHover={handleNodeHover}
      onNodeMove={handleNodeMove}
      onNodeLeave={handleNodeLeave}
      onNodeClick={handleNodeClick}
    />
  );

  const wrappedCustomLink = (
    props: Omit<
      CustomLinkProps,
      | "colors"
      | "hoveredLink"
      | "onLinkHover"
      | "onLinkMove"
      | "onLinkLeave"
      | "onLinkClick"
    >,
  ) => (
    <CustomLink
      {...props}
      colors={colors}
      hoveredLink={hoveredLink}
      onLinkHover={handleLinkHover}
      onLinkMove={handleLinkMove}
      onLinkLeave={handleLinkLeave}
      onLinkClick={handleLinkClick}
    />
  );

  // Check if there's actual data to display (links with values > 0)
  const hasData = data.links.some((link) => link.value > 0);

  if (!hasData) {
    return (
      <div
        className="flex items-center justify-center"
        style={{ height: `${height}px` }}
      >
        <div className="flex flex-col items-center gap-2 text-center">
          <Info size={48} className="text-text-neutral-tertiary" />
          <p className="text-text-neutral-secondary text-sm">
            No failed findings to display
          </p>
        </div>
      </div>
    );
  }

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
      {zeroDataProviders.length > 0 && (
        <div className="border-divider-primary mt-4 border-t pt-4">
          <p className="text-text-neutral-tertiary mb-3 text-xs font-medium tracking-wide uppercase">
            Providers with no failed findings
          </p>
          <div className="flex flex-wrap gap-4">
            {zeroDataProviders.map((provider) => {
              const IconComponent = PROVIDER_ICONS[provider.displayName];
              return (
                <div
                  key={provider.id}
                  className="flex items-center gap-2 text-sm"
                >
                  {IconComponent && <IconComponent width={20} height={20} />}
                  <span className="text-text-neutral-secondary">
                    {provider.displayName}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
