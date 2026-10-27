import { Sparkles } from "lucide-react";
import type { ComponentProps } from "react";

import { LighthouseIconWithAura } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import { cn } from "@/lib/utils";

// Inline invitation to hand a task to Lighthouse AI. Compound usage:
// LighthouseCallout > LighthouseCalloutIcon + LighthouseCalloutBody
// (Title, Description) + LighthouseCalloutActions (LighthouseCalloutAction).
export const LIGHTHOUSE_CALLOUT_LAYOUT = {
  /** A row: icon, copy and actions side by side. */
  INLINE: "inline",
  /** A row until lg, then a narrow column for a sidebar. */
  SIDEBAR: "sidebar",
} as const;

export type LighthouseCalloutLayout =
  (typeof LIGHTHOUSE_CALLOUT_LAYOUT)[keyof typeof LIGHTHOUSE_CALLOUT_LAYOUT];

const LAYOUT_STYLES = {
  [LIGHTHOUSE_CALLOUT_LAYOUT.INLINE]: "",
  [LIGHTHOUSE_CALLOUT_LAYOUT.SIDEBAR]:
    "lg:flex-col lg:items-start lg:gap-3 lg:px-4 lg:py-4",
} as const satisfies Record<LighthouseCalloutLayout, string>;

interface LighthouseCalloutProps extends ComponentProps<"section"> {
  layout?: LighthouseCalloutLayout;
}

export function LighthouseCallout({
  className,
  layout = LIGHTHOUSE_CALLOUT_LAYOUT.INLINE,
  ...props
}: LighthouseCalloutProps) {
  return (
    <section
      data-slot="lighthouse-callout"
      data-layout={layout}
      className={cn(
        "gradient-border-lighthouse bg-bg-neutral-primary bg-lighthouse-soft group/lighthouse-callout flex flex-col gap-3 rounded-2xl px-4 py-3.5 sm:flex-row sm:items-center sm:gap-4",
        LAYOUT_STYLES[layout],
        className,
      )}
      {...props}
    />
  );
}

export function LighthouseCalloutIcon({
  className,
  ...props
}: ComponentProps<"span">) {
  return (
    <span
      aria-hidden
      className={cn(
        "bg-bg-neutral-secondary ring-border-lighthouse hidden size-10 shrink-0 items-center justify-center rounded-full ring-1 sm:flex",
        className,
      )}
      {...props}
    >
      <LighthouseIconWithAura size={22} />
    </span>
  );
}

export function LighthouseCalloutBody({
  className,
  ...props
}: ComponentProps<"div">) {
  return (
    <div
      className={cn("flex min-w-0 flex-1 flex-col gap-0.5", className)}
      {...props}
    />
  );
}

export function LighthouseCalloutTitle({
  className,
  ...props
}: ComponentProps<"p">) {
  return (
    <p
      className={cn(
        "text-text-neutral-primary text-sm leading-5 font-semibold",
        className,
      )}
      {...props}
    />
  );
}

export function LighthouseCalloutDescription({
  className,
  ...props
}: ComponentProps<"div">) {
  return (
    <div
      className={cn(
        "text-text-neutral-secondary text-sm leading-5 text-pretty",
        className,
      )}
      {...props}
    />
  );
}

// Holds the primary action plus any secondary ones (e.g. a docs link).
export function LighthouseCalloutActions({
  className,
  ...props
}: ComponentProps<"div">) {
  return (
    <div
      className={cn(
        // A sidebar stacks the actions so their height never depends on the copy.
        "flex shrink-0 items-center gap-2 group-data-[layout=sidebar]/lighthouse-callout:lg:flex-col-reverse group-data-[layout=sidebar]/lighthouse-callout:lg:items-start",
        className,
      )}
      {...props}
    />
  );
}

export function LighthouseCalloutAction({
  children,
  ...props
}: Omit<ComponentProps<typeof Button>, "variant">) {
  return (
    <Button type="button" variant="lighthouse" {...props}>
      <Sparkles aria-hidden />
      {children}
    </Button>
  );
}
