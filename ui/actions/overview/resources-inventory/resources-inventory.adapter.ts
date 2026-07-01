import { LucideIcon } from "lucide-react";
import {
  Activity,
  BarChart3,
  Bot,
  Boxes,
  Building2,
  CloudCog,
  Container,
  Database,
  FolderOpen,
  GitBranch,
  MessageSquare,
  Network,
  Server,
  Shield,
  SquareFunction,
  UserRoundSearch,
  Webhook,
} from "lucide-react";

import {
  ResourceGroupOverview,
  ResourceGroupOverviewResponse,
  SeverityBreakdown,
} from "./types";

// Resource group IDs matching API values from ResourceGroup field specification
export const RESOURCE_GROUP_IDS = {
  COMPUTE: "compute",
  CONTAINER: "container",
  SERVERLESS: "serverless",
  DATABASE: "database",
  STORAGE: "storage",
  NETWORK: "network",
  IAM: "IAM",
  MESSAGING: "messaging",
  SECURITY: "security",
  MONITORING: "monitoring",
  API_GATEWAY: "api_gateway",
  AI_ML: "ai_ml",
  GOVERNANCE: "governance",
  COLLABORATION: "collaboration",
  DEVOPS: "devops",
  ANALYTICS: "analytics",
} as const;

export type ResourceGroupId =
  (typeof RESOURCE_GROUP_IDS)[keyof typeof RESOURCE_GROUP_IDS];

export interface ResourceInventoryItem {
  id: string;
  label: string;
  icon: LucideIcon;
  totalResources: number;
  totalFindings: number;
  failedFindings: number;
  newFailedFindings: number;
  severity: SeverityBreakdown;
}

interface ResourceGroupConfig {
  label: string;
  icon: LucideIcon;
}

const RESOURCE_GROUP_CONFIG: Record<ResourceGroupId, ResourceGroupConfig> = {
  [RESOURCE_GROUP_IDS.COMPUTE]: {
    label: "Compute",
    icon: Server,
  },
  [RESOURCE_GROUP_IDS.CONTAINER]: {
    label: "Container",
    icon: Container,
  },
  [RESOURCE_GROUP_IDS.SERVERLESS]: {
    label: "Serverless",
    icon: SquareFunction,
  },
  [RESOURCE_GROUP_IDS.DATABASE]: {
    label: "Database",
    icon: Database,
  },
  [RESOURCE_GROUP_IDS.STORAGE]: {
    label: "Storage",
    icon: FolderOpen,
  },
  [RESOURCE_GROUP_IDS.NETWORK]: {
    label: "Network",
    icon: Network,
  },
  [RESOURCE_GROUP_IDS.IAM]: {
    label: "IAM",
    icon: UserRoundSearch,
  },
  [RESOURCE_GROUP_IDS.MESSAGING]: {
    label: "Messaging",
    icon: MessageSquare,
  },
  [RESOURCE_GROUP_IDS.SECURITY]: {
    label: "Security",
    icon: Shield,
  },
  [RESOURCE_GROUP_IDS.MONITORING]: {
    label: "Monitoring",
    icon: Activity,
  },
  [RESOURCE_GROUP_IDS.API_GATEWAY]: {
    label: "API Gateway",
    icon: Webhook,
  },
  [RESOURCE_GROUP_IDS.AI_ML]: {
    label: "AI/ML",
    icon: Bot,
  },
  [RESOURCE_GROUP_IDS.GOVERNANCE]: {
    label: "Governance",
    icon: Building2,
  },
  [RESOURCE_GROUP_IDS.COLLABORATION]: {
    label: "Collaboration",
    icon: Boxes,
  },
  [RESOURCE_GROUP_IDS.DEVOPS]: {
    label: "DevOps",
    icon: GitBranch,
  },
  [RESOURCE_GROUP_IDS.ANALYTICS]: {
    label: "Analytics",
    icon: BarChart3,
  },
};

// Default icon for unknown resource groups
const DEFAULT_ICON = CloudCog;

// Order in which resource groups should be displayed
const RESOURCE_GROUP_ORDER: ResourceGroupId[] = [
  RESOURCE_GROUP_IDS.COMPUTE,
  RESOURCE_GROUP_IDS.CONTAINER,
  RESOURCE_GROUP_IDS.SERVERLESS,
  RESOURCE_GROUP_IDS.DATABASE,
  RESOURCE_GROUP_IDS.STORAGE,
  RESOURCE_GROUP_IDS.NETWORK,
  RESOURCE_GROUP_IDS.IAM,
  RESOURCE_GROUP_IDS.MESSAGING,
  RESOURCE_GROUP_IDS.SECURITY,
  RESOURCE_GROUP_IDS.MONITORING,
  RESOURCE_GROUP_IDS.API_GATEWAY,
  RESOURCE_GROUP_IDS.AI_ML,
  RESOURCE_GROUP_IDS.GOVERNANCE,
  RESOURCE_GROUP_IDS.COLLABORATION,
  RESOURCE_GROUP_IDS.DEVOPS,
  RESOURCE_GROUP_IDS.ANALYTICS,
];

function mapResourceInventoryItem(
  item: ResourceGroupOverview,
): ResourceInventoryItem {
  const id = item.id;
  const config = RESOURCE_GROUP_CONFIG[id as ResourceGroupId];

  return {
    id,
    label: config?.label || formatResourceGroupLabel(id),
    icon: config?.icon || DEFAULT_ICON,
    totalResources: item.attributes.resources_count,
    totalFindings: item.attributes.total_findings,
    failedFindings: item.attributes.failed_findings,
    newFailedFindings: item.attributes.new_failed_findings,
    severity: item.attributes.severity,
  };
}

/**
 * Formats a resource group ID into a human-readable label.
 * Handles snake_case and capitalizes appropriately.
 */
function formatResourceGroupLabel(id: string): string {
  return id
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

/**
 * Adapts the resource group overview API response to a format suitable for the UI.
 * Returns the items in a consistent order as defined by RESOURCE_GROUP_ORDER.
 *
 * @param response - The resource group overview API response
 * @returns An array of ResourceInventoryItem objects sorted by the predefined order
 */
export function adaptResourceGroupOverview(
  response: ResourceGroupOverviewResponse | undefined,
): ResourceInventoryItem[] {
  if (!response?.data || response.data.length === 0) {
    return [];
  }

  // Create a map for quick lookup
  const itemsMap = new Map<string, ResourceGroupOverview>();
  for (const item of response.data) {
    itemsMap.set(item.id, item);
  }

  // Return items in the predefined order
  const sortedItems: ResourceInventoryItem[] = [];
  for (const id of RESOURCE_GROUP_ORDER) {
    const item = itemsMap.get(id);
    if (item) {
      sortedItems.push(mapResourceInventoryItem(item));
    }
  }

  // Include any items that might be in the response but not in our predefined order
  for (const item of response.data) {
    if (!RESOURCE_GROUP_ORDER.includes(item.id as ResourceGroupId)) {
      sortedItems.push(mapResourceInventoryItem(item));
    }
  }

  return sortedItems;
}

/**
 * Returns all resource groups with default/empty values.
 * Useful for showing all groups even when no data is available.
 */
export function getEmptyResourceInventoryItems(): ResourceInventoryItem[] {
  return RESOURCE_GROUP_ORDER.map((id) => {
    const config = RESOURCE_GROUP_CONFIG[id];
    return {
      id,
      label: config.label,
      icon: config.icon,
      totalResources: 0,
      totalFindings: 0,
      failedFindings: 0,
      newFailedFindings: 0,
      severity: {
        informational: 0,
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
      },
    };
  });
}
