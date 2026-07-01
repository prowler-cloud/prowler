import { AttackSurfaceOverview, AttackSurfaceOverviewResponse } from "./types";

const ATTACK_SURFACE_IDS = {
  INTERNET_EXPOSED: "internet-exposed",
  SECRETS: "secrets",
  PRIVILEGE_ESCALATION: "privilege-escalation",
  EC2_IMDSV1: "ec2-imdsv1",
} as const;

export type AttackSurfaceId =
  (typeof ATTACK_SURFACE_IDS)[keyof typeof ATTACK_SURFACE_IDS];

export interface AttackSurfaceItem {
  id: AttackSurfaceId;
  label: string;
  failedFindings: number;
  totalFindings: number;
}

const ATTACK_SURFACE_LABELS: Record<AttackSurfaceId, string> = {
  [ATTACK_SURFACE_IDS.INTERNET_EXPOSED]: "Internet Exposed Resources",
  [ATTACK_SURFACE_IDS.SECRETS]: "Exposed Secrets",
  [ATTACK_SURFACE_IDS.PRIVILEGE_ESCALATION]: "IAM Policy Privilege Escalation",
  [ATTACK_SURFACE_IDS.EC2_IMDSV1]: "EC2 with IMDSv1 Enabled",
};

const ATTACK_SURFACE_ORDER: AttackSurfaceId[] = [
  ATTACK_SURFACE_IDS.INTERNET_EXPOSED,
  ATTACK_SURFACE_IDS.SECRETS,
  ATTACK_SURFACE_IDS.PRIVILEGE_ESCALATION,
  ATTACK_SURFACE_IDS.EC2_IMDSV1,
];

function mapAttackSurfaceItem(item: AttackSurfaceOverview): AttackSurfaceItem {
  const id = item.id as AttackSurfaceId;
  return {
    id,
    label: ATTACK_SURFACE_LABELS[id] || item.id,
    failedFindings: item.attributes.failed_findings,
    totalFindings: item.attributes.total_findings,
  };
}

/**
 * Adapts the attack surface overview API response to a format suitable for the UI.
 * Returns the items in a consistent order as defined by ATTACK_SURFACE_ORDER.
 *
 * @param response - The attack surface overview API response
 * @returns An array of AttackSurfaceItem objects sorted by the predefined order
 */
export function adaptAttackSurfaceOverview(
  response: AttackSurfaceOverviewResponse | undefined,
): AttackSurfaceItem[] {
  if (!response?.data || response.data.length === 0) {
    return [];
  }

  // Create a map for quick lookup
  const itemsMap = new Map<string, AttackSurfaceOverview>();
  for (const item of response.data) {
    itemsMap.set(item.id, item);
  }

  // Return items in the predefined order
  const sortedItems: AttackSurfaceItem[] = [];
  for (const id of ATTACK_SURFACE_ORDER) {
    const item = itemsMap.get(id);
    if (item) {
      sortedItems.push(mapAttackSurfaceItem(item));
    }
  }

  // Include any items that might be in the response but not in our predefined order
  for (const item of response.data) {
    if (!ATTACK_SURFACE_ORDER.includes(item.id as AttackSurfaceId)) {
      sortedItems.push(mapAttackSurfaceItem(item));
    }
  }

  return sortedItems;
}
