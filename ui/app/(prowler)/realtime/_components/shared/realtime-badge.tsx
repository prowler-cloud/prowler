import type { ReactNode } from "react";

import {
  BADGE_TONE,
  type BadgeDescriptor,
  type BadgeTone,
} from "@/app/(prowler)/realtime/_lib/display";
import { Badge } from "@/components/shadcn";

const VARIANT_BY_TONE = {
  [BADGE_TONE.SUCCESS]: "success",
  [BADGE_TONE.WARNING]: "warning",
  [BADGE_TONE.ERROR]: "error",
  [BADGE_TONE.INFO]: "info",
  [BADGE_TONE.TAG]: "tag",
  [BADGE_TONE.OUTLINE]: "outline",
} as const satisfies Record<BadgeTone, string>;

interface RealtimeBadgeProps {
  descriptor: BadgeDescriptor;
  children?: ReactNode;
}

/** A status from `display.ts` in the shared Badge. */
export function RealtimeBadge({ descriptor, children }: RealtimeBadgeProps) {
  return (
    <Badge variant={VARIANT_BY_TONE[descriptor.tone]}>
      {children}
      {descriptor.label}
    </Badge>
  );
}
