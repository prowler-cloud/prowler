import { ArrowRight } from "lucide-react";
import Link from "next/link";

import { LighthouseIcon } from "@/components/icons/Icons";
import { Card, CardContent } from "@/components/shadcn";

import type { LighthouseOverviewBannerHref } from "../_lib/lighthouse-banner";

interface LighthouseOverviewBannerProps {
  href: LighthouseOverviewBannerHref;
}

export function LighthouseOverviewBanner({
  href,
}: LighthouseOverviewBannerProps) {
  return (
    <Link
      href={href}
      className="group focus-visible:ring-border-input-primary block rounded-xl focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none"
    >
      <Card
        variant="base"
        padding="none"
        className="group-hover:border-border-input-primary transition-colors"
      >
        <CardContent className="flex min-w-0 items-center justify-between gap-4 px-4 py-3 sm:px-5">
          <div className="flex min-w-0 items-center gap-3">
            <span className="border-border-neutral-tertiary bg-bg-neutral-tertiary flex size-9 shrink-0 items-center justify-center rounded-md border">
              <LighthouseIcon className="size-5" />
            </span>
            <div className="min-w-0">
              <p className="text-text-neutral-primary text-sm font-medium">
                Lighthouse AI
              </p>
              <p className="text-text-neutral-secondary text-sm">
                Find and remediate which actually matters.
              </p>
            </div>
          </div>
          <ArrowRight className="text-text-neutral-tertiary size-4 shrink-0 transition-transform group-hover:translate-x-0.5" />
        </CardContent>
      </Card>
    </Link>
  );
}
