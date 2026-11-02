import { ComponentProps } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import {
  AttackerStart,
  ISSUE_OUTCOME_LABEL,
  IssueAttributes,
  LEG_STATE,
} from "@/types/issues";

export interface RiskFactor {
  label: string;
  variant: ComponentProps<typeof Badge>["variant"];
  /** Why the factor is on the issue, shown on hover. */
  title: string;
}

/** Where the attacker starts, as a chip; a foothold is a precondition, not an exposure. */
const START_FACTOR: Record<AttackerStart, Omit<RiskFactor, "title">> = {
  internet: { label: "Internet-reachable", variant: "error" },
  authenticated_principal: {
    label: "Any signed-in identity",
    variant: "error",
  },
  credential_leak: { label: "Leaked credential", variant: "error" },
  external_user: { label: "Outside user", variant: "error" },
  foothold: { label: "Needs a foothold", variant: "warning" },
};

/**
 * The conditions that line up to make the issue, read from the legs the engine
 * already decided, so a chip can never contradict the verdict beside it. Each
 * chip's hover text is the leg's own explanation.
 */
export const riskFactors = (issue: IssueAttributes): RiskFactor[] => {
  const { legs } = issue;
  const factors: RiskFactor[] = [];

  if (issue.attacker_start) {
    factors.push({
      ...START_FACTOR[issue.attacker_start],
      title: "Where the attacker has to be standing for the path to start",
    });
  }
  if (legs.access?.state === LEG_STATE.YES) {
    factors.push({
      label: "Access possible",
      variant: "error",
      title: legs.access.text,
    });
  }
  if (legs.target?.state === LEG_STATE.YES) {
    factors.push({
      label: issue.outcome
        ? ISSUE_OUTCOME_LABEL[issue.outcome]
        : "Worth taking",
      variant: "error",
      title: legs.target.text,
    });
  }
  // Controls is the leg where "yes" is the good news: a control is in force.
  if (legs.controls?.state === LEG_STATE.YES) {
    factors.push({
      label: "Blocked by a control",
      variant: "success",
      title: legs.controls.text,
    });
  } else if (legs.controls?.state === LEG_STATE.NO) {
    factors.push({
      label: "No control blocking",
      variant: "warning",
      title: legs.controls.text,
    });
  }

  return factors;
};
