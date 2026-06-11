import type { AttackPathQuery, AttackPathScan } from "@/types/attack-paths";
import { ATTACK_PATH_QUERY_IDS } from "@/types/attack-paths";

import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
} from "./tour-types";

export const attackPathsTour = defineTour({
  id: "attack-paths",
  version: 1,
  coversFiles: [
    "ui/app/(prowler)/attack-paths/**",
    "ui/components/attack-paths/**",
  ],
  steps: [
    {
      title: "Welcome to Attack Paths",
      description:
        "Attack Paths visualizes how a compromise in one resource could spread through your cloud. It's currently available for AWS accounts only.",
    },
    {
      target: "intro",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Start with a scan",
      description:
        "Attack Paths analyses are generated from your existing AWS scans. Each scan is a point-in-time snapshot of one account.",
    },
    {
      target: "scan-list",
      side: TOUR_STEP_SIDES.TOP,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Pick a scan",
      description:
        "Each row is a scan. Click the radio button on the left to select one.",
    },
    {
      target: "query-selector",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Choose a query",
      description:
        "Predefined queries cover common risk patterns (privilege escalation, public exposure, lateral movement). You can also write your own openCypher.",
    },
    {
      target: "execute-button",
      side: TOUR_STEP_SIDES.TOP,
      align: TOUR_STEP_ALIGNMENTS.END,
      title: "Run it whenever you're ready",
      description:
        "Click Execute Query to see the graph with the possible attack paths.",
    },
    {
      title: "You're all set",
      description:
        "Explore the attack paths and dig into anything that looks risky.",
    },
  ],
});

export type AttackPathsTourTarget = NonNullable<
  (typeof attackPathsTour.steps)[number]["target"]
>;

// Demo-pick logic lives here so page code never decides what to auto-run.
// Preferred demo query: well-known and usually returns findings.
const PREFERRED_DEMO_QUERY_ID = "aws-iam-statements-allow-all-actions";

const isReadyScan = (scan: AttackPathScan): boolean =>
  scan.attributes.graph_data_ready;

// Prefer a ready AWS scan; fall back to any ready scan for non-AWS tenants.
export function pickDemoScan(
  scans: readonly AttackPathScan[],
): AttackPathScan | undefined {
  const preferredAws = scans.find(
    (scan) => isReadyScan(scan) && scan.attributes.provider_type === "aws",
  );
  return preferredAws ?? scans.find(isReadyScan);
}

// Runnable = no required params and not Custom (needs manual Cypher).
export function pickDemoQuery(
  queries: readonly AttackPathQuery[],
): AttackPathQuery | undefined {
  const isRunnable = (query: AttackPathQuery): boolean =>
    query.id !== ATTACK_PATH_QUERY_IDS.CUSTOM &&
    query.attributes.parameters.length === 0;
  const preferredIam = queries.find(
    (query) => query.id === PREFERRED_DEMO_QUERY_ID && isRunnable(query),
  );
  return preferredIam ?? queries.find(isRunnable);
}
