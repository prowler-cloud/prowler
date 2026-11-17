import type { ComponentProps } from "react";

import { cn } from "@/lib/utils";

// Empty, error and onboarding states. Compound usage:
// StatusPanel > StatusPanelIcon + StatusPanelBody (Title, Description)
// + StatusPanelActions.
export const STATUS_PANEL_LAYOUT = {
  /** A centered column that takes the place of the content. */
  CENTERED: "centered",
  /** A row: icon, copy and actions side by side from `sm` up. */
  INLINE: "inline",
} as const;

export type StatusPanelLayout =
  (typeof STATUS_PANEL_LAYOUT)[keyof typeof STATUS_PANEL_LAYOUT];

const LAYOUT_STYLES = {
  [STATUS_PANEL_LAYOUT.CENTERED]:
    "flex-col items-center gap-3 px-6 py-10 text-center",
  [STATUS_PANEL_LAYOUT.INLINE]:
    "flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:gap-4",
} as const satisfies Record<StatusPanelLayout, string>;

interface StatusPanelProps extends ComponentProps<"section"> {
  layout?: StatusPanelLayout;
}

export function StatusPanel({
  className,
  layout = STATUS_PANEL_LAYOUT.CENTERED,
  ...props
}: StatusPanelProps) {
  return (
    <section
      data-slot="status-panel"
      data-layout={layout}
      className={cn(
        "group/status-panel border-border-neutral-secondary bg-bg-neutral-secondary flex rounded-xl border",
        LAYOUT_STYLES[layout],
        className,
      )}
      {...props}
    />
  );
}

export function StatusPanelIcon({
  className,
  ...props
}: ComponentProps<"span">) {
  return (
    <span
      aria-hidden
      data-slot="status-panel-icon"
      className={cn(
        "bg-bg-neutral-tertiary text-text-neutral-secondary border-border-neutral-secondary flex size-12 shrink-0 items-center justify-center rounded-xl border [&>svg]:size-6",
        // Inline rows drop the icon below sm so the copy keeps the width.
        "group-data-[layout=inline]/status-panel:hidden group-data-[layout=inline]/status-panel:size-8 group-data-[layout=inline]/status-panel:rounded-lg group-data-[layout=inline]/status-panel:sm:flex group-data-[layout=inline]/status-panel:[&>svg]:size-4",
        className,
      )}
      {...props}
    />
  );
}

export function StatusPanelBody({
  className,
  ...props
}: ComponentProps<"div">) {
  return (
    <div
      data-slot="status-panel-body"
      className={cn(
        "flex flex-col items-center gap-1 group-data-[layout=inline]/status-panel:min-w-0 group-data-[layout=inline]/status-panel:flex-1 group-data-[layout=inline]/status-panel:items-start",
        className,
      )}
      {...props}
    />
  );
}

// An h2: the page h1 lives in the navbar.
export function StatusPanelTitle({
  className,
  ...props
}: ComponentProps<"h2">) {
  return (
    <h2
      data-slot="status-panel-title"
      className={cn(
        "text-text-neutral-primary text-base font-semibold group-data-[layout=inline]/status-panel:text-sm",
        className,
      )}
      {...props}
    />
  );
}

export function StatusPanelDescription({
  className,
  ...props
}: ComponentProps<"p">) {
  return (
    <p
      data-slot="status-panel-description"
      className={cn(
        "text-text-neutral-secondary max-w-prose text-sm text-pretty",
        className,
      )}
      {...props}
    />
  );
}

export function StatusPanelActions({
  className,
  ...props
}: ComponentProps<"div">) {
  return (
    <div
      data-slot="status-panel-actions"
      className={cn(
        "flex flex-wrap items-center justify-center gap-2 group-data-[layout=centered]/status-panel:pt-1 group-data-[layout=inline]/status-panel:shrink-0 group-data-[layout=inline]/status-panel:justify-start",
        className,
      )}
      {...props}
    />
  );
}
