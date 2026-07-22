export interface SankeyNodeLike {
  name: string;
}

export interface SankeyLinkLike {
  source: number;
}

export interface SankeyLayoutInput {
  baseHeight: number;
  nodes: SankeyNodeLike[];
  links: SankeyLinkLike[];
}

export interface SankeyLayoutConfig {
  height: number;
  nodePadding: number;
}

const SANKEY_DEFAULT_NODE_PADDING = 50;
const SANKEY_MIN_NODE_PADDING = 14;
const SANKEY_HEIGHT_GROWTH_PER_PROVIDER = 64;
const SANKEY_BASE_PROVIDER_COUNT = 6;
const SANKEY_MAX_HEIGHT = 1400;

const getProviderNodeCount = ({ nodes, links }: SankeyLayoutInput): number => {
  const uniqueSourceIndexes = new Set<number>();

  links.forEach((link) => {
    uniqueSourceIndexes.add(link.source);
  });

  if (uniqueSourceIndexes.size > 0) {
    return uniqueSourceIndexes.size;
  }

  return Math.max(0, nodes.length - 5);
};

const getNodePaddingForProviderCount = (providerNodeCount: number): number => {
  const compactedProviders = Math.max(
    0,
    providerNodeCount - SANKEY_BASE_PROVIDER_COUNT,
  );
  return Math.max(
    SANKEY_MIN_NODE_PADDING,
    Math.round(SANKEY_DEFAULT_NODE_PADDING - compactedProviders * 2),
  );
};

export const getSankeyLayoutConfig = (
  params: SankeyLayoutInput,
): SankeyLayoutConfig => {
  const providerNodeCount = getProviderNodeCount(params);
  const extraProviders = Math.max(
    0,
    providerNodeCount - SANKEY_BASE_PROVIDER_COUNT,
  );
  const dynamicHeight = Math.min(
    SANKEY_MAX_HEIGHT,
    Math.round(
      params.baseHeight + extraProviders * SANKEY_HEIGHT_GROWTH_PER_PROVIDER,
    ),
  );

  return {
    height: dynamicHeight,
    nodePadding: getNodePaddingForProviderCount(providerNodeCount),
  };
};
