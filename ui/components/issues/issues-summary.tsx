import { CircleHelp, Layers, ShieldCheck, TriangleAlert } from "lucide-react";

import { CardVariant, ResourceStatsCard } from "@/components/shadcn";
import { IssuesOverviewResponse } from "@/types/issues";

/** The fold, as the tiles above the issue list. */
export const IssuesSummary = ({
  overview,
}: {
  overview: IssuesOverviewResponse["data"]["attributes"];
}) => {
  return (
    <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
      <ResourceStatsCard
        badge={{ icon: Layers, count: overview.findings }}
        label="Failed findings folded"
      />
      <ResourceStatsCard
        accent={CardVariant.info}
        badge={{
          icon: Layers,
          count: overview.issues,
          variant: CardVariant.info,
        }}
        label="Issues"
      />
      <ResourceStatsCard
        badge={{
          icon: TriangleAlert,
          count: overview.actionable,
          variant: CardVariant.fail,
        }}
        label="Exploitable or likely"
      />
      <ResourceStatsCard
        badge={{
          icon: ShieldCheck,
          count: overview.not_exploitable,
          variant: CardVariant.pass,
        }}
        label="Not exploitable"
        stats={[
          {
            icon: Layers,
            label: `${overview.not_exploitable_findings} findings`,
          },
        ]}
      />
      <ResourceStatsCard
        badge={{
          icon: CircleHelp,
          count: overview.unknown,
          variant: CardVariant.warning,
        }}
        label="Unknown"
      />
    </div>
  );
};
