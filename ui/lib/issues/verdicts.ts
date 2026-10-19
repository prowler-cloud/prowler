import { ComponentProps } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import { LegName, LegState, Verdict } from "@/types/issues";

interface VerdictDisplay {
  id: Verdict;
  label: string;
  variant: ComponentProps<typeof Badge>["variant"];
}

export const VERDICTS: VerdictDisplay[] = [
  { id: "exploitable", label: "Exploitable", variant: "error" },
  { id: "likely", label: "Likely", variant: "error" },
  { id: "conditional", label: "Conditional", variant: "outline" },
  { id: "not_exploitable", label: "Not exploitable", variant: "success" },
  { id: "unknown", label: "Unknown", variant: "tag" },
];

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
