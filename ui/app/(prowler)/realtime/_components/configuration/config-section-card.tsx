"use client";

import { Check } from "lucide-react";
import type { ReactNode } from "react";

import {
  STEP_STATE,
  type StepState,
} from "@/app/(prowler)/realtime/_lib/setup";
import { Badge, Button, Card } from "@/components/shadcn";
import { cn } from "@/lib/utils";

const MARKER_STYLES: Record<StepState, string> = {
  [STEP_STATE.DONE]: "bg-bg-pass-secondary text-text-success-primary",
  [STEP_STATE.CURRENT]: "bg-button-primary text-black",
  [STEP_STATE.TODO]:
    "bg-bg-neutral-tertiary text-text-neutral-tertiary border border-border-neutral-secondary",
};

interface ConfigSectionCardProps {
  id: string;
  number: number;
  title: string;
  description: string;
  summary: string;
  state: StepState;
  required: boolean;
  open: boolean;
  onOpen: () => void;
  /** Extra status next to the title (e.g. the feed's health). */
  badge?: ReactNode;
  /** Why the section cannot be opened yet; disables the button. */
  lockedReason?: string;
  children: ReactNode;
}

/** One configuration section: a summary row, or its form when open. */
export function ConfigSectionCard({
  id,
  number,
  title,
  description,
  summary,
  state,
  required,
  open,
  onOpen,
  badge,
  lockedReason,
  children,
}: ConfigSectionCardProps) {
  const done = state === STEP_STATE.DONE;
  const headingId = `${id}-title`;

  return (
    <Card
      variant="base"
      padding="none"
      id={id}
      aria-labelledby={headingId}
      className={cn(
        "scroll-mt-24 gap-0",
        open && "border-border-neutral-tertiary",
      )}
    >
      <div
        className={cn(
          "flex flex-wrap items-center gap-3 px-[18px] py-4",
          open && "border-border-neutral-secondary border-b",
        )}
      >
        <span
          aria-hidden
          className={cn(
            "flex size-7 shrink-0 items-center justify-center rounded-full text-xs font-semibold",
            MARKER_STYLES[state],
          )}
        >
          {done ? <Check className="size-3.5" strokeWidth={3} /> : number}
        </span>
        <div className="flex min-w-0 flex-1 flex-col gap-0.5">
          <h2
            id={headingId}
            className="text-text-neutral-primary text-sm font-semibold"
          >
            {title}
            <span className="sr-only">{done ? " (done)" : ""}</span>
          </h2>
          <p className="text-text-neutral-tertiary text-xs">
            {open ? description : summary}
          </p>
        </div>
        {badge}
        {!done && (
          <Badge variant="tag">{required ? "Required" : "Optional"}</Badge>
        )}
        {!open && (
          <Button
            variant="outline"
            size="sm"
            onClick={onOpen}
            disabled={Boolean(lockedReason)}
            aria-label={`${done ? "Edit" : "Set up"} ${title}`}
          >
            {done ? "Edit" : "Set up"}
          </Button>
        )}
      </div>
      {!open && lockedReason && (
        <p className="text-text-neutral-tertiary px-[18px] pb-4 text-xs">
          {lockedReason}
        </p>
      )}
      {open && children}
    </Card>
  );
}

interface SectionFooterProps {
  onCancel: () => void;
  submitLabel: string;
  pending: boolean;
  disabled: boolean;
}

/** Cancel and Save at the bottom of an open section's form. */
export function SectionFooter({
  onCancel,
  submitLabel,
  pending,
  disabled,
}: SectionFooterProps) {
  return (
    <div className="border-border-neutral-secondary flex justify-end gap-2 border-t px-[18px] py-3">
      <Button type="button" variant="outline" onClick={onCancel}>
        Cancel
      </Button>
      <Button type="submit" disabled={disabled || pending}>
        {pending ? "Saving…" : submitLabel}
      </Button>
    </div>
  );
}
