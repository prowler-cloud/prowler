import { Check, Flag } from "lucide-react";

import { Badge } from "@/components/shadcn";

export const TriageStatusValues = {
  IN_PROGRESS: "in_progress",
  RESOLVED: "resolved",
  NONE: "none",
} as const;

export type TriageStatus =
  (typeof TriageStatusValues)[keyof typeof TriageStatusValues];

interface TriageBadgeProps {
  status: TriageStatus;
  count: number;
}

const TriageBadge = ({ status, count }: TriageBadgeProps) => {
  if (status === TriageStatusValues.NONE) {
    return null;
  }

  const isInProgress = status === TriageStatusValues.IN_PROGRESS;

  return (
    <Badge variant="tag" className="rounded text-sm">
      {isInProgress ? (
        <Flag className="size-3 fill-sky-400 text-sky-400" />
      ) : (
        <Check className="size-3 text-green-300" />
      )}
      <span className="font-bold">{count}</span>
      <span className="font-normal">
        {isInProgress ? "In-progress" : "Resolved"}
      </span>
    </Badge>
  );
};

interface ImpactedResourcesCellProps {
  impacted: number;
  total: number;
  inProgress?: number;
  resolved?: number;
}

export const ImpactedResourcesCell = ({
  impacted,
  total,
  inProgress = 0,
  resolved = 0,
}: ImpactedResourcesCellProps) => {
  return (
    <div className="flex items-center gap-6">
      <Badge variant="tag" className="rounded text-sm">
        <span className="font-bold">{impacted}</span>
        <span className="font-normal">of</span>
        <span className="font-bold">{total}</span>
      </Badge>

      {inProgress > 0 && (
        <TriageBadge
          status={TriageStatusValues.IN_PROGRESS}
          count={inProgress}
        />
      )}

      {resolved > 0 && (
        <TriageBadge status={TriageStatusValues.RESOLVED} count={resolved} />
      )}
    </div>
  );
};
