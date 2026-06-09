import type { AttackPathScan } from "@/types/attack-paths";
import { SCAN_STATES } from "@/types/attack-paths";

export const ATTACK_PATHS_VIEW_STATES = {
  LOADING: "loading",
  ERROR: "error",
  NO_SCANS: "no-scans",
  SCAN_RUNNING: "scan-running",
  GRAPH_BUILDING: "graph-building",
  NO_GRAPH_DATA: "no-graph-data",
  READY: "ready",
} as const;

export type AttackPathsViewState =
  (typeof ATTACK_PATHS_VIEW_STATES)[keyof typeof ATTACK_PATHS_VIEW_STATES];

interface GetAttackPathsViewStateInput {
  scansLoading: boolean;
  loadError: boolean;
  scans: AttackPathScan[];
}

/**
 * Single source of truth for what the Attack Paths page shows. The full-page
 * message owns every "not queryable yet" state; the workflow renders only once
 * at least one provider's graph is ready.
 */
export const getAttackPathsViewState = ({
  scansLoading,
  loadError,
  scans,
}: GetAttackPathsViewStateInput): AttackPathsViewState => {
  if (scansLoading) return ATTACK_PATHS_VIEW_STATES.LOADING;
  if (loadError) return ATTACK_PATHS_VIEW_STATES.ERROR;
  if (scans.length === 0) return ATTACK_PATHS_VIEW_STATES.NO_SCANS;

  if (scans.some((s) => s.attributes.graph_data_ready)) {
    return ATTACK_PATHS_VIEW_STATES.READY;
  }
  if (scans.some((s) => s.attributes.state === SCAN_STATES.EXECUTING)) {
    return ATTACK_PATHS_VIEW_STATES.GRAPH_BUILDING;
  }
  if (
    scans.some(
      (s) =>
        s.attributes.state === SCAN_STATES.SCHEDULED ||
        s.attributes.state === SCAN_STATES.AVAILABLE,
    )
  ) {
    return ATTACK_PATHS_VIEW_STATES.SCAN_RUNNING;
  }
  return ATTACK_PATHS_VIEW_STATES.NO_GRAPH_DATA;
};

/** Highest progress among scans whose graph is actively building. */
export const getGraphBuildingProgress = (scans: AttackPathScan[]): number =>
  scans
    .filter((s) => s.attributes.state === SCAN_STATES.EXECUTING)
    .reduce((max, s) => Math.max(max, s.attributes.progress), 0);
