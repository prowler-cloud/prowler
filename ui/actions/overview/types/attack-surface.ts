// Attack Surface Overview Types
// Corresponds to the /overviews/attack_surface endpoint

import { OverviewResponseMeta } from "./common";

export interface AttackSurfaceOverviewAttributes {
  total_findings: number;
  failed_findings: number;
  muted_failed_findings: number;
  check_ids: string[];
}

export interface AttackSurfaceOverview {
  type: "attack-surface-overviews";
  id: string;
  attributes: AttackSurfaceOverviewAttributes;
}

export interface AttackSurfaceOverviewResponse {
  data: AttackSurfaceOverview[];
  meta: OverviewResponseMeta;
}
