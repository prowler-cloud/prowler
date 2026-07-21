"use client";

import type { ComponentProps, ReactNode } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Popover,
  PopoverAnchor,
  PopoverClose,
  PopoverContent,
} from "@/components/shadcn/popover";

interface DiscoveryCalloutProps {
  // Controlled: the caller decides when the hint shows and persists "seen".
  open: boolean;
  // Fired on every dismissal path: the action button, outside click, Escape.
  onDismiss: () => void;
  children: ReactNode;
}

// One-time feature-discovery callout anchored to the control it introduces.
// Compound usage: wrap the anchor element in DiscoveryCalloutAnchor and
// render one DiscoveryCalloutContent beside it, all inside DiscoveryCallout.
export function DiscoveryCallout({
  open,
  onDismiss,
  children,
}: DiscoveryCalloutProps) {
  return (
    <Popover
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) onDismiss();
      }}
    >
      {children}
    </Popover>
  );
}

export const DiscoveryCalloutAnchor = PopoverAnchor;

interface DiscoveryCalloutContentProps {
  title: string;
  description: ReactNode;
  dismissLabel?: string;
  side?: ComponentProps<typeof PopoverContent>["side"];
  align?: ComponentProps<typeof PopoverContent>["align"];
  "data-testid"?: string;
}

export function DiscoveryCalloutContent({
  title,
  description,
  dismissLabel = "Got it",
  side = "bottom",
  align = "end",
  "data-testid": testId,
}: DiscoveryCalloutContentProps) {
  return (
    <PopoverContent
      side={side}
      align={align}
      sideOffset={8}
      // A discovery hint must never steal focus from what the user is doing.
      onOpenAutoFocus={(event) => event.preventDefault()}
      data-testid={testId}
    >
      <div className="flex flex-col gap-2">
        <p className="text-text-neutral-primary text-sm font-medium">{title}</p>
        <p className="text-text-neutral-secondary text-sm">{description}</p>
        <div className="flex justify-end">
          <PopoverClose asChild>
            <Button type="button" variant="outline" size="sm">
              {dismissLabel}
            </Button>
          </PopoverClose>
        </div>
      </div>
    </PopoverContent>
  );
}
