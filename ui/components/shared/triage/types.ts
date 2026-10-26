import type { ComponentProps } from "react";

import type { SelectTrigger } from "@/components/shadcn/select/select";
import type {
  FindingTriageModalStatus,
  FindingTriageStatus,
} from "@/types/findings-triage";

export type TriageStatusPickerSize = NonNullable<
  ComponentProps<typeof SelectTrigger>["size"]
>;

export interface TriageStatusPickerProps {
  disabled: boolean;
  size?: TriageStatusPickerSize;
  value: FindingTriageStatus;
  statusValues: readonly FindingTriageModalStatus[];
  showManualPassTooltip?: boolean;
  onValueChange: (status: FindingTriageModalStatus) => void;
}

export interface TriageStatusBadgeProps {
  status: FindingTriageStatus;
  showLabel?: boolean;
}
