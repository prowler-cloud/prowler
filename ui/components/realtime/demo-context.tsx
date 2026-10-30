"use client";

import Link from "next/link";
import { createContext, type ReactNode, useContext } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import {
  DEMO_BANNER_TITLE,
  DEMO_TOOLTIP,
  LIGHTHOUSE_CHAT_PATH,
  setupHref,
} from "@/lib/realtime/demo";

const DemoContext = createContext(false);

/** Everything below shows made-up sample data, and says so. */
export function DemoProvider({
  demo,
  children,
}: {
  demo: boolean;
  children: ReactNode;
}) {
  return <DemoContext.Provider value={demo}>{children}</DemoContext.Provider>;
}

export const useIsDemo = () => useContext(DemoContext);

/** Marks a card or table header as sample data, for sight and for screen readers. */
export function DemoBadge() {
  return (
    <Badge variant="warning" size="sm" data-testid="demo-badge">
      DEMO
      <span className="sr-only"> data: made up, not your account</span>
    </Badge>
  );
}

/** The badge when the surrounding view is a demo; nothing otherwise. */
export function DemoBadgeIfDemo() {
  return useIsDemo() ? <DemoBadge /> : null;
}

/** Small, secondary: the same setup, done by chat. */
export function LighthouseSetupLink({ className }: { className?: string }) {
  return (
    <span className={className}>
      Prefer to do this by chat?{" "}
      <Link
        href={LIGHTHOUSE_CHAT_PATH}
        className="text-button-tertiary underline underline-offset-4"
      >
        Ask Lighthouse AI to set it up
      </Link>
    </span>
  );
}

/** Impossible to miss, on every dashboard tab and on the sample anomaly page. */
export function DemoBanner({ providerId }: { providerId?: string }) {
  return (
    <Alert variant="warning" role="status" aria-label="Demo data">
      <AlertTitle className="line-clamp-none text-base">
        {DEMO_BANNER_TITLE}
      </AlertTitle>
      <AlertDescription>
        <p>
          Everything on this page is sample data. Nothing here comes from your
          AWS account, and nothing is switched on yet.
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2">
          <Button asChild size="sm">
            <Link href={setupHref(providerId)}>Set up Prowler Realtime</Link>
          </Button>
          <LighthouseSetupLink className="text-xs" />
        </div>
      </AlertDescription>
    </Alert>
  );
}

/**
 * Wraps a disabled write control in demo mode, so a tooltip can say why.
 * A disabled button takes no hover, hence the focusable wrapper.
 */
export function DemoDisabled({ children }: { children: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex">
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent>{DEMO_TOOLTIP}</TooltipContent>
    </Tooltip>
  );
}
