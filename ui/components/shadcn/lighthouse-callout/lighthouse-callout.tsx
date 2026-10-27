import { Sparkles } from "lucide-react";
import type { ComponentProps } from "react";

import { LighthouseIconWithAura } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import { cn } from "@/lib/utils";

// Inline invitation to hand a task to Lighthouse AI. Compound usage:
// LighthouseCallout > LighthouseCalloutIcon + LighthouseCalloutBody
// (Title, Description) + LighthouseCalloutActions (LighthouseCalloutAction).
export function LighthouseCallout({
  className,
  ...props
}: ComponentProps<"section">) {
  return (
    <section
      data-slot="lighthouse-callout"
      className={cn(
        "gradient-border-lighthouse bg-bg-neutral-primary bg-lighthouse-soft flex flex-col gap-3 rounded-2xl px-4 py-3.5 sm:flex-row sm:items-center sm:gap-4",
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
      className={cn("flex shrink-0 items-center gap-2", className)}
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
