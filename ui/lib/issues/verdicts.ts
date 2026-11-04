import { ComponentProps } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import {
  ATTACKER_START_LABEL,
  IssueAttributes,
  ISSUE_OUTCOME_LABEL,
  LegName,
  LegState,
  Verdict,
} from "@/types/issues";

/** The colour family a verdict reads in, shared by the overview card and the tabs. */
export const VERDICT_TONE = {
  fail: "fail",
  warning: "warning",
  pass: "pass",
  neutral: "neutral",
} as const;

export type VerdictTone = (typeof VERDICT_TONE)[keyof typeof VERDICT_TONE];

interface VerdictDisplay {
  id: Verdict;
  label: string;
  variant: ComponentProps<typeof Badge>["variant"];
  tone: VerdictTone;
}

export const VERDICTS: VerdictDisplay[] = [
  {
    id: "exploitable",
    label: "Exploitable",
    variant: "error",
    tone: VERDICT_TONE.fail,
  },
  { id: "likely", label: "Likely", variant: "error", tone: VERDICT_TONE.fail },
  {
    id: "conditional",
    label: "Conditional",
    variant: "outline",
    tone: VERDICT_TONE.warning,
  },
  {
    id: "not_exploitable",
    label: "Not exploitable",
    variant: "success",
    tone: VERDICT_TONE.pass,
  },
  {
    id: "unknown",
    label: "Unknown",
    variant: "tag",
    tone: VERDICT_TONE.neutral,
  },
];

export const LEG_LABELS: Record<LegName, string> = {
  reachability: "Reachability",
  access: "Access",
  target: "Target",
  controls: "Controls",
  verification: "Verification",
};

export const LEG_QUESTIONS: Record<LegName, string> = {
  reachability: "Can an attacker reach it?",
  access: "Can an attacker authenticate or bypass authentication?",
  target: "Is there a target worth reaching?",
  controls: "Are protective controls in place?",
  verification: "Would the activity be detected?",
};

export const LEG_STATE_LABELS: Record<LegState, string> = {
  yes: "Yes",
  no: "No",
  partial: "Partly",
  unknown: "Unknown",
};

/** "The internet → Data exposure", or null for issues that are not one path. */
export const attackPathLabel = ({
  attacker_start,
  outcome,
}: Pick<IssueAttributes, "attacker_start" | "outcome">) =>
  attacker_start && outcome
    ? `${ATTACKER_START_LABEL[attacker_start]} → ${ISSUE_OUTCOME_LABEL[outcome]}`
    : null;

const LEG_GOOD_WHEN_YES: Record<LegName, boolean> = {
  reachability: false,
  access: false,
  target: false,
  controls: true,
  verification: true,
};

export const legBadgeVariant = (
  leg: LegName,
  state: LegState,
): ComponentProps<typeof Badge>["variant"] => {
  if (state === "unknown") return "tag";
  if (state === "partial") return "outline";
  return (state === "yes") === LEG_GOOD_WHEN_YES[leg] ? "success" : "error";
};

/** Per-verdict counts from a summary payload, zero where the API sent none. */
export const verdictCounts = (
  attributes: Partial<Record<Verdict, number>> | undefined,
): Record<Verdict, number> => ({
  exploitable: attributes?.exploitable ?? 0,
  likely: attributes?.likely ?? 0,
  conditional: attributes?.conditional ?? 0,
  not_exploitable: attributes?.not_exploitable ?? 0,
  unknown: attributes?.unknown ?? 0,
});
