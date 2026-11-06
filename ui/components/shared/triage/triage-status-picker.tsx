"use client";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
} from "@/components/shadcn/select/select";
import { TRIAGE_STATUS_TEXT_CLASS } from "@/lib/triage";
import { cn } from "@/lib/utils";
import {
  FINDING_TRIAGE_STATUS,
  FINDING_TRIAGE_STATUS_LABELS,
  MANUAL_PASS_NOTE_REQUIRED_COPY,
  type FindingTriageModalStatus,
} from "@/types/findings-triage";

import type { TriageStatusPickerProps } from "./types";

export function TriageStatusPicker({
  disabled,
  size = "sm",
  value,
  statusValues,
  showManualPassTooltip = false,
  onValueChange,
}: TriageStatusPickerProps) {
  return (
    <Select
      value={value}
      disabled={disabled}
      onValueChange={(nextStatus) => {
        if (statusValues.includes(nextStatus as FindingTriageModalStatus)) {
          onValueChange(nextStatus as FindingTriageModalStatus);
        }
      }}
    >
      <SelectTrigger
        aria-label="Triage status"
        disabled={disabled}
        size={size}
        iconSize="sm"
      >
        <span className={cn("truncate", TRIAGE_STATUS_TEXT_CLASS[value])}>
          {FINDING_TRIAGE_STATUS_LABELS[value]}
        </span>
      </SelectTrigger>
      <SelectContent>
        {statusValues.map((status) => {
          const shouldExplainManualPass =
            showManualPassTooltip && status === FINDING_TRIAGE_STATUS.RESOLVED;
          return (
            <SelectItem
              key={status}
              value={status}
              aria-label={FINDING_TRIAGE_STATUS_LABELS[status]}
            >
              <span
                className={cn("truncate", TRIAGE_STATUS_TEXT_CLASS[status])}
              >
                {FINDING_TRIAGE_STATUS_LABELS[status]}
              </span>
              {shouldExplainManualPass && (
                <span
                  className="text-text-neutral-secondary text-xs font-normal normal-case"
                  aria-hidden="true"
                >
                  {MANUAL_PASS_NOTE_REQUIRED_COPY}
                </span>
              )}
            </SelectItem>
          );
        })}
      </SelectContent>
    </Select>
  );
}
