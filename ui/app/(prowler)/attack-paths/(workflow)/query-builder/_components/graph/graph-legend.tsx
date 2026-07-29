"use client";

import { useTheme } from "next-themes";
import type { ElementType, ReactNode } from "react";

import { Card, CardContent } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import type { AttackPathGraphData, GraphNode } from "@/types/attack-paths";

import {
  getNodeBorderColor,
  getNodeColor,
  GRAPH_ALERT_BORDER_COLOR,
  GRAPH_EDGE_COLOR_DARK,
  GRAPH_EDGE_COLOR_LIGHT,
  GRAPH_EDGE_HIGHLIGHT_COLOR,
  GRAPH_NODE_BORDER_COLORS,
  GRAPH_NODE_COLORS,
} from "../../_lib/graph-colors";
import { resolveHiddenFindingIds } from "../../_lib/graph-utils";
import { isProwlerFindingNode } from "../../_lib/node-types";
import { NODE_CATEGORY, resolveNodeVisual } from "../../_lib/node-visuals";

const LEGEND_PREVIEW = {
  BADGE_RADIUS: 16,
  BADGE_CENTER: 18,
  ICON_SIZE: 20,
  ICON_OFFSET: 8,
  SVG_SIZE: 36,
} as const;

const EDGE_VARIANT = {
  NORMAL: "normal",
  FINDING: "finding",
  HIGHLIGHTED: "highlighted",
} as const;

type EdgeVariant = (typeof EDGE_VARIANT)[keyof typeof EDGE_VARIANT];

interface LegendVisualItem {
  label: string;
  description: string;
  Icon: ElementType;
  fillColor: string;
  borderColor: string;
  glow?: boolean;
}

interface LegendStateItem {
  label: string;
  description: string;
  fillColor: string;
  borderColor: string;
  strokeWidth: number;
  glowColor?: string;
}

interface LegendEdgeItem {
  label: string;
  description: string;
  variant: EdgeVariant;
}

interface LegendSectionProps {
  title: string;
  children: ReactNode;
}

interface LegendItemProps {
  label: string;
  description: string;
  children: ReactNode;
}

interface GraphLegendProps {
  data?: AttackPathGraphData;
  expandedResources?: ReadonlySet<string>;
  isFilteredView?: boolean;
}

interface GraphLegendState {
  visibleNodes: GraphNode[];
  visibleNodeIds: Set<string>;
  visibleFindingIds: Set<string>;
  visibleEdges: Array<{ source: string; target: string }>;
  resourcesWithFindings: Set<string>;
}

const buildNode = (
  labels: string[],
  properties: GraphNode["properties"] = {},
): GraphNode => ({
  id: labels[0] ?? "legend-node",
  labels,
  properties,
});

const buildVisualItem = (
  label: string,
  description: string,
  node: GraphNode,
  fillColor: string,
  borderColor: string,
  glow = false,
): LegendVisualItem => ({
  label,
  description,
  Icon: resolveNodeVisual(node).Icon,
  fillColor,
  borderColor,
  glow,
});

const providerRootItem = buildVisualItem(
  "Provider",
  "Cloud account, tenant, project, organization, or cluster entry point.",
  buildNode(["AWSAccount"], { name: "Provider root" }),
  GRAPH_NODE_COLORS.awsAccount,
  GRAPH_NODE_BORDER_COLORS.awsAccount,
);

const findingRiskItems: LegendVisualItem[] = [
  buildVisualItem(
    "Critical",
    "Highest-risk finding node with severity-colored badge and glow.",
    buildNode(["ProwlerFinding"], { severity: "critical" }),
    GRAPH_NODE_COLORS.critical,
    GRAPH_NODE_BORDER_COLORS.critical,
    true,
  ),
  buildVisualItem(
    "High",
    "High-risk finding node with severity-colored badge and glow.",
    buildNode(["ProwlerFinding"], { severity: "high" }),
    GRAPH_NODE_COLORS.high,
    GRAPH_NODE_BORDER_COLORS.high,
    true,
  ),
  buildVisualItem(
    "Medium",
    "Medium-risk finding node with severity-colored badge and glow.",
    buildNode(["ProwlerFinding"], { severity: "medium" }),
    GRAPH_NODE_COLORS.medium,
    GRAPH_NODE_BORDER_COLORS.medium,
    true,
  ),
  buildVisualItem(
    "Low / Info",
    "Lower-risk informational findings use the info-style risk icon.",
    buildNode(["ProwlerFinding"], { severity: "info" }),
    GRAPH_NODE_COLORS.info,
    GRAPH_NODE_BORDER_COLORS.info,
    true,
  ),
];

const stateItems: LegendStateItem[] = [
  {
    label: "Selected node",
    description: "Active node with a stronger animated selection ring.",
    fillColor: GRAPH_NODE_COLORS.default,
    borderColor: GRAPH_EDGE_HIGHLIGHT_COLOR,
    strokeWidth: 4,
    glowColor: GRAPH_EDGE_HIGHLIGHT_COLOR,
  },
  {
    label: "Node with findings",
    description: "Resource node linked to one or more findings.",
    fillColor: GRAPH_NODE_COLORS.default,
    borderColor: GRAPH_ALERT_BORDER_COLOR,
    strokeWidth: 3,
    glowColor: GRAPH_ALERT_BORDER_COLOR,
  },
];

const edgeItems: LegendEdgeItem[] = [
  {
    label: "Normal edge",
    description: "Relationship between resources in the attack path.",
    variant: EDGE_VARIANT.NORMAL,
  },
  {
    label: "Finding edge",
    description: "Animated dashed edge that connects a resource to a finding.",
    variant: EDGE_VARIANT.FINDING,
  },
  {
    label: "Highlighted path",
    description:
      "Prowler green path shown when hovering or selecting related graph nodes.",
    variant: EDGE_VARIANT.HIGHLIGHTED,
  },
];

const isFindingNode = (node: GraphNode): boolean =>
  isProwlerFindingNode(node.labels);

const getGraphEdges = (
  data: AttackPathGraphData,
): Array<{ source: string; target: string }> =>
  data.relationships ?? data.edges ?? [];

const resolveLegendState = (
  data: AttackPathGraphData,
  expandedResources: ReadonlySet<string>,
  isFilteredView: boolean,
): GraphLegendState => {
  const findingNodeIds = new Set(
    data.nodes.filter(isFindingNode).map((node) => node.id),
  );
  const findingToResources = new Map<string, Set<string>>();
  const resourcesWithFindings = new Set<string>();
  const graphEdges = getGraphEdges(data);

  for (const edge of graphEdges) {
    const sourceIsFinding = findingNodeIds.has(edge.source);
    const targetIsFinding = findingNodeIds.has(edge.target);

    if (sourceIsFinding) {
      resourcesWithFindings.add(edge.target);
      const resources = findingToResources.get(edge.source) ?? new Set();
      resources.add(edge.target);
      findingToResources.set(edge.source, resources);
    }

    if (targetIsFinding) {
      resourcesWithFindings.add(edge.source);
      const resources = findingToResources.get(edge.target) ?? new Set();
      resources.add(edge.source);
      findingToResources.set(edge.target, resources);
    }
  }

  const hiddenFindingIds = resolveHiddenFindingIds({
    expandedResources,
    findingNodeIds,
    findingToResources,
    isFilteredView,
  });

  const visibleNodes = data.nodes.filter(
    (node) => !hiddenFindingIds.has(node.id),
  );
  const visibleNodeIds = new Set(visibleNodes.map((node) => node.id));
  const visibleFindingIds = new Set(
    visibleNodes.filter(isFindingNode).map((node) => node.id),
  );
  const visibleEdges = graphEdges.filter(
    (edge) =>
      visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target),
  );

  return {
    visibleNodes,
    visibleNodeIds,
    visibleFindingIds,
    visibleEdges,
    resourcesWithFindings,
  };
};

const resolveNodeTypeItems = (
  visibleNodes: GraphNode[],
): LegendVisualItem[] => {
  const itemsByType = new Map<string, LegendVisualItem>();

  for (const node of visibleNodes) {
    if (isFindingNode(node)) continue;

    const visual = resolveNodeVisual(node);
    if (visual.category === NODE_CATEGORY.ACCOUNT) continue;

    const key = `${visual.category}:${visual.description}`;

    if (!itemsByType.has(key)) {
      itemsByType.set(key, {
        label: visual.description,
        description: `${visual.description} node`,
        Icon: visual.Icon,
        fillColor: getNodeColor(node.labels),
        borderColor: getNodeBorderColor(node.labels),
      });
    }
  }

  return Array.from(itemsByType.values());
};

const resolveFindingRiskItems = (
  visibleNodes: GraphNode[],
): LegendVisualItem[] => {
  const visibleSeverities = new Set(
    visibleNodes
      .filter(isFindingNode)
      .map((node) => String(node.properties.severity ?? "").toLowerCase()),
  );

  return findingRiskItems.filter((item) => {
    if (item.label === "Low / Info") {
      return (
        visibleSeverities.has("low") ||
        visibleSeverities.has("info") ||
        visibleSeverities.has("informational")
      );
    }

    return visibleSeverities.has(item.label.toLowerCase());
  });
};

const LegendSection = ({ title, children }: LegendSectionProps) => (
  <section className="bg-bg-neutral-secondary/60 border-border-neutral-primary flex w-full min-w-0 flex-col gap-2 rounded-lg border p-3 sm:w-fit sm:max-w-full">
    <h3 className="text-text-neutral-secondary text-[0.68rem] leading-none font-semibold tracking-wide uppercase">
      {title}
    </h3>
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      {children}
    </div>
  </section>
);

const LegendItem = ({ label, description, children }: LegendItemProps) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <div
        className="hover:bg-bg-neutral-tertiary/70 inline-flex cursor-help items-center gap-2 rounded-full px-1.5 py-1 transition-colors"
        role="img"
        aria-label={`${label}: ${description}`}
      >
        {children}
        <span className="text-text-neutral-secondary text-xs whitespace-nowrap">
          {label}
        </span>
      </div>
    </TooltipTrigger>
    <TooltipContent>{description}</TooltipContent>
  </Tooltip>
);

const BadgePreview = ({
  Icon,
  fillColor,
  borderColor,
  glow,
}: LegendVisualItem) => (
  <svg
    width={LEGEND_PREVIEW.SVG_SIZE}
    height={LEGEND_PREVIEW.SVG_SIZE}
    viewBox="0 0 36 36"
    aria-hidden="true"
    className="overflow-visible"
  >
    {glow && (
      <circle
        cx={LEGEND_PREVIEW.BADGE_CENTER}
        cy={LEGEND_PREVIEW.BADGE_CENTER}
        r={LEGEND_PREVIEW.BADGE_RADIUS + 4}
        stroke={borderColor}
        strokeOpacity={0.28}
        strokeWidth={6}
        fill={borderColor}
        fillOpacity={0.14}
      />
    )}
    <circle
      cx={LEGEND_PREVIEW.BADGE_CENTER}
      cy={LEGEND_PREVIEW.BADGE_CENTER}
      r={LEGEND_PREVIEW.BADGE_RADIUS}
      fill={fillColor}
      fillOpacity={0.94}
      stroke={borderColor}
      strokeWidth={glow ? 2.5 : 1.5}
    />
    <g
      transform={`translate(${LEGEND_PREVIEW.ICON_OFFSET}, ${LEGEND_PREVIEW.ICON_OFFSET})`}
    >
      <Icon
        aria-hidden="true"
        color="#ffffff"
        focusable="false"
        height={LEGEND_PREVIEW.ICON_SIZE}
        role="presentation"
        size={LEGEND_PREVIEW.ICON_SIZE}
        width={LEGEND_PREVIEW.ICON_SIZE}
      />
    </g>
  </svg>
);

const StatePreview = ({
  fillColor,
  borderColor,
  strokeWidth,
  glowColor,
}: LegendStateItem) => (
  <svg width="36" height="36" viewBox="0 0 36 36" aria-hidden="true">
    {glowColor && (
      <circle cx="18" cy="18" r="20" fill={glowColor} fillOpacity="0.18" />
    )}
    <circle
      cx="18"
      cy="18"
      r="16"
      fill={fillColor}
      fillOpacity="0.92"
      stroke={borderColor}
      strokeWidth={strokeWidth}
    />
  </svg>
);

const EdgePreview = ({
  variant,
  edgeColor,
}: {
  variant: EdgeVariant;
  edgeColor: string;
}) => {
  const isFindingEdge = variant === EDGE_VARIANT.FINDING;
  const isHighlightedPath = variant === EDGE_VARIANT.HIGHLIGHTED;
  const strokeColor = isHighlightedPath
    ? GRAPH_EDGE_HIGHLIGHT_COLOR
    : edgeColor;

  return (
    <svg
      width="56"
      height="20"
      viewBox="0 0 56 20"
      aria-hidden="true"
      className="overflow-visible"
    >
      {isHighlightedPath && (
        <line
          x1="4"
          y1="10"
          x2="40"
          y2="10"
          stroke={GRAPH_EDGE_HIGHLIGHT_COLOR}
          strokeOpacity="0.32"
          strokeWidth="7"
          strokeLinecap="round"
        />
      )}
      <line
        x1="4"
        y1="10"
        x2="40"
        y2="10"
        stroke={strokeColor}
        strokeWidth={isHighlightedPath ? 3 : 2.5}
        strokeLinecap="round"
        strokeDasharray={isFindingEdge ? "8 6" : undefined}
      />
      <polygon points="40,5 52,10 40,15" fill={strokeColor} />
    </svg>
  );
};

/**
 * Compact semantic legend for the Attack Paths graph visual language.
 */
export const GraphLegend = ({
  data,
  expandedResources = new Set(),
  isFilteredView = false,
}: GraphLegendProps) => {
  const { resolvedTheme } = useTheme();

  if (!data || data.nodes.length === 0) {
    return null;
  }

  const legendState = resolveLegendState(
    data,
    expandedResources,
    isFilteredView,
  );
  const providerItem = legendState.visibleNodes.some(
    (node) => resolveNodeVisual(node).category === NODE_CATEGORY.ACCOUNT,
  )
    ? providerRootItem
    : null;
  const visibleNodeTypeItems = resolveNodeTypeItems(legendState.visibleNodes);
  const visibleFindingRiskItems = resolveFindingRiskItems(
    legendState.visibleNodes,
  );
  const visibleStateItems = stateItems.filter(
    (item) =>
      item.label === "Selected node" ||
      Array.from(legendState.resourcesWithFindings).some((resourceId) =>
        legendState.visibleNodeIds.has(resourceId),
      ),
  );
  const visibleEdgeItems = edgeItems.filter((item) => {
    if (item.variant === EDGE_VARIANT.FINDING) {
      return legendState.visibleEdges.some(
        (edge) =>
          legendState.visibleFindingIds.has(edge.source) ||
          legendState.visibleFindingIds.has(edge.target),
      );
    }

    return legendState.visibleEdges.length > 0;
  });

  if (
    !providerItem &&
    visibleNodeTypeItems.length === 0 &&
    visibleFindingRiskItems.length === 0 &&
    visibleStateItems.length === 0 &&
    visibleEdgeItems.length === 0
  ) {
    return null;
  }

  const edgeColor =
    resolvedTheme === "dark" ? GRAPH_EDGE_COLOR_DARK : GRAPH_EDGE_COLOR_LIGHT;

  return (
    <Card className="w-full border-0">
      <CardContent className="p-3">
        <TooltipProvider>
          <div className="flex w-full flex-wrap items-stretch gap-2">
            {providerItem && (
              <LegendSection title="Provider roots">
                <LegendItem {...providerItem}>
                  <BadgePreview {...providerItem} />
                </LegendItem>
              </LegendSection>
            )}

            {visibleNodeTypeItems.length > 0 && (
              <LegendSection title="Node types">
                {visibleNodeTypeItems.map((item) => (
                  <LegendItem key={item.label} {...item}>
                    <BadgePreview {...item} />
                  </LegendItem>
                ))}
              </LegendSection>
            )}

            {visibleFindingRiskItems.length > 0 && (
              <LegendSection title="Findings by risk">
                {visibleFindingRiskItems.map((item) => (
                  <LegendItem key={item.label} {...item}>
                    <BadgePreview {...item} />
                  </LegendItem>
                ))}
              </LegendSection>
            )}

            {visibleStateItems.length > 0 && (
              <LegendSection title="States">
                {visibleStateItems.map((item) => (
                  <LegendItem key={item.label} {...item}>
                    <StatePreview {...item} />
                  </LegendItem>
                ))}
              </LegendSection>
            )}

            {visibleEdgeItems.length > 0 && (
              <LegendSection title="Edges">
                {visibleEdgeItems.map((item) => (
                  <LegendItem key={item.label} {...item}>
                    <EdgePreview variant={item.variant} edgeColor={edgeColor} />
                  </LegendItem>
                ))}
              </LegendSection>
            )}
          </div>
        </TooltipProvider>
      </CardContent>
    </Card>
  );
};
