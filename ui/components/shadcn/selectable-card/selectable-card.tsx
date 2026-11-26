import type { ComponentProps } from "react";

import { cn } from "@/lib/utils";

interface SelectableCardProps extends ComponentProps<"button"> {
  selected: boolean;
}

/** A card that is one choice in a list: pressed while it is the picked one. */
export function SelectableCard({
  selected,
  className,
  ...props
}: SelectableCardProps) {
  return (
    <button
      type="button"
      data-slot="selectable-card"
      aria-pressed={selected}
      className={cn(
        "border-border-neutral-secondary bg-bg-neutral-secondary hover:bg-bg-neutral-tertiary rounded-[12px] border p-3 text-left transition-colors",
        selected &&
          "border-border-input-primary-press bg-bg-neutral-tertiary ring-border-input-primary-press ring-1",
        className,
      )}
      {...props}
    />
  );
}
