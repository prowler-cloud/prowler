import { LucideIcon } from "lucide-react";
import {
  Combine,
  Container,
  Database,
  FolderOpen,
  Network,
  Server,
  SquareFunction,
  UserRoundSearch,
} from "lucide-react";

import {
  ResourcesInventoryOverview,
  ResourcesInventoryOverviewResponse,
} from "./types";

export const RESOURCE_CATEGORY_IDS = {
  HOSTS: "hosts",
  CONTAINER: "container",
  DATABASE: "database",
  STORAGE: "storage",
  NETWORK: "network",
  QUEUE: "queue",
  IDENTITY: "identity",
  SERVERLESS: "serverless",
} as const;

export type ResourceCategoryId =
  (typeof RESOURCE_CATEGORY_IDS)[keyof typeof RESOURCE_CATEGORY_IDS];

export interface ResourceInventoryItem {
  id: ResourceCategoryId;
  label: string;
  icon: LucideIcon;
  totalResources: number;
  failedFindings: number;
  newFindings: number;
  misconfigurations: number;
}

interface CategoryConfig {
  label: string;
  icon: LucideIcon;
}

const RESOURCE_CATEGORY_CONFIG: Record<ResourceCategoryId, CategoryConfig> = {
  [RESOURCE_CATEGORY_IDS.HOSTS]: {
    label: "Hosts",
    icon: Server,
  },
  [RESOURCE_CATEGORY_IDS.CONTAINER]: {
    label: "Container",
    icon: Container,
  },
  [RESOURCE_CATEGORY_IDS.DATABASE]: {
    label: "Database",
    icon: Database,
  },
  [RESOURCE_CATEGORY_IDS.STORAGE]: {
    label: "Storage",
    icon: FolderOpen,
  },
  [RESOURCE_CATEGORY_IDS.NETWORK]: {
    label: "Network",
    icon: Network,
  },
  [RESOURCE_CATEGORY_IDS.QUEUE]: {
    label: "Queue",
    icon: Combine,
  },
  [RESOURCE_CATEGORY_IDS.IDENTITY]: {
    label: "Identity",
    icon: UserRoundSearch,
  },
  [RESOURCE_CATEGORY_IDS.SERVERLESS]: {
    label: "Serverless",
    icon: SquareFunction,
  },
};

const RESOURCE_CATEGORY_ORDER: ResourceCategoryId[] = [
  RESOURCE_CATEGORY_IDS.HOSTS,
  RESOURCE_CATEGORY_IDS.CONTAINER,
  RESOURCE_CATEGORY_IDS.DATABASE,
  RESOURCE_CATEGORY_IDS.STORAGE,
  RESOURCE_CATEGORY_IDS.NETWORK,
  RESOURCE_CATEGORY_IDS.QUEUE,
  RESOURCE_CATEGORY_IDS.IDENTITY,
  RESOURCE_CATEGORY_IDS.SERVERLESS,
];

function mapResourceInventoryItem(
  item: ResourcesInventoryOverview,
): ResourceInventoryItem {
  const id = item.id as ResourceCategoryId;
  const config = RESOURCE_CATEGORY_CONFIG[id];

  return {
    id,
    label: config?.label || item.id,
    icon: config?.icon || Server,
    totalResources: item.attributes.total_resources,
    failedFindings: item.attributes.failed_findings,
    newFindings: item.attributes.new_findings,
    misconfigurations: item.attributes.misconfigurations,
  };
}

/**
 * Adapts the resources inventory overview API response to a format suitable for the UI.
 * Returns the items in a consistent order as defined by RESOURCE_CATEGORY_ORDER.
 *
 * @param response - The resources inventory overview API response
 * @returns An array of ResourceInventoryItem objects sorted by the predefined order
 */
export function adaptResourcesInventoryOverview(
  response: ResourcesInventoryOverviewResponse | undefined,
): ResourceInventoryItem[] {
  if (!response?.data || response.data.length === 0) {
    return [];
  }

  // Create a map for quick lookup
  const itemsMap = new Map<string, ResourcesInventoryOverview>();
  for (const item of response.data) {
    itemsMap.set(item.id, item);
  }

  // Return items in the predefined order
  const sortedItems: ResourceInventoryItem[] = [];
  for (const id of RESOURCE_CATEGORY_ORDER) {
    const item = itemsMap.get(id);
    if (item) {
      sortedItems.push(mapResourceInventoryItem(item));
    }
  }

  // Include any items that might be in the response but not in our predefined order
  for (const item of response.data) {
    if (!RESOURCE_CATEGORY_ORDER.includes(item.id as ResourceCategoryId)) {
      sortedItems.push(mapResourceInventoryItem(item));
    }
  }

  return sortedItems;
}

/**
 * Returns all resource categories with default/empty values.
 * Useful for showing all categories even when no data is available.
 */
export function getEmptyResourceInventoryItems(): ResourceInventoryItem[] {
  return RESOURCE_CATEGORY_ORDER.map((id) => {
    const config = RESOURCE_CATEGORY_CONFIG[id];
    return {
      id,
      label: config.label,
      icon: config.icon,
      totalResources: 0,
      failedFindings: 0,
      newFindings: 0,
      misconfigurations: 0,
    };
  });
}
