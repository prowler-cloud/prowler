"use client";

import { SquareArrowOutUpRight } from "lucide-react";
import Image from "next/image";
import Link from "next/link";

import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { Button } from "@/components/shadcn/button/button";
import { Card, CardContent } from "@/components/shadcn/card/card";
import type { CrossProviderInsights } from "@/lib/compliance/cross-provider-insights";
import { getProwlerHubComplianceUrl } from "@/lib/compliance/prowler-hub";

import { ProviderCoveragePanel } from "./provider-coverage-panel";
import { ScoreDonut } from "./score-donut";
import { TopFailingDomainsPanel } from "./top-failing-domains-panel";
import { formatTitle } from "./utils";

interface CrossProviderHeaderProps {
  /** Universal framework key (``CSA-CCM``). Drives the icon lookup. */
  framework: string;
  /** Display name. */
  name: string;
  /** Version label (``4.0``). */
  version: string;
  /** Long description from the universal JSON. */
  description: string;
  /** Universal framework id (e.g. ``cis_controls_8.1``) — builds the
   *  Prowler Hub reference link. */
  complianceId: string;
  insights: CrossProviderInsights;
  /** Click handler when a top-failing-domain entry is selected. */
  onDomainSelect?: (domainName: string) => void;
}

/**
 * Three-pane operations header for the cross-provider compliance view.
 *
 * Replaces the old single-card stat grid + provider strip with:
 *   1. Score donut + pass/fail/manual breakdown.
 *   2. Provider coverage list (every compatible provider with its
 *      per-provider score and a clear "no scan yet" marker).
 *   3. Top failing domains teaser — clickable anchors so the user can
 *      jump straight to where it hurts.
 *
 * On screens narrower than ``lg`` the panes stack vertically. The
 * framework metadata strip (icon + title + description) sits above the
 * three columns to keep the cards equal-height.
 */
export const CrossProviderHeader = ({
  framework,
  name,
  version,
  description,
  complianceId,
  insights,
  onDomainSelect,
}: CrossProviderHeaderProps) => {
  return (
    <Card variant="base" padding="md">
      <CardContent className="flex flex-col gap-5 p-0">
        <div className="flex flex-wrap items-center gap-3">
          {getComplianceIcon(framework) && (
            <div className="flex h-12 w-12 min-w-12 shrink-0 items-center justify-center rounded-md border border-gray-300 bg-white">
              <Image
                src={getComplianceIcon(framework)}
                alt={`${framework} logo`}
                width={40}
                height={40}
                className="h-10 w-10 object-contain"
              />
            </div>
          )}
          <div className="flex min-w-0 flex-1 flex-col">
            <div className="flex flex-wrap items-baseline gap-2">
              <h2 className="truncate text-lg leading-6 font-bold">
                {name || formatTitle(framework)}
              </h2>
              {version && (
                <span className="text-text-neutral-secondary font-mono text-xs">
                  v{version}
                </span>
              )}
              <span className="border-border-neutral-secondary text-text-neutral-secondary rounded border px-1.5 py-0.5 text-[10px] font-semibold tracking-wider uppercase">
                Universal
              </span>
              <Button
                variant="link"
                size="link-xs"
                className="shrink-0 whitespace-nowrap"
                asChild
              >
                <Link
                  href={getProwlerHubComplianceUrl(complianceId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  prefetch={false}
                >
                  View on Prowler Hub
                  <SquareArrowOutUpRight className="size-3" />
                </Link>
              </Button>
            </div>
            {description && (
              <p className="text-text-neutral-secondary mt-1 line-clamp-2 text-xs">
                {description}
              </p>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[auto_1fr_1fr]">
          <div className="border-border-neutral-secondary flex flex-col items-center justify-center rounded-lg border bg-gray-50 px-4 py-4 dark:bg-gray-900/30">
            <ScoreDonut
              scorePercent={insights.scorePercent}
              pass={insights.pass}
              fail={insights.fail}
              manual={insights.manual}
              total={insights.total}
            />
          </div>
          <ProviderCoveragePanel coverage={insights.providerCoverage} />
          <TopFailingDomainsPanel
            domains={insights.domainsByFailCount}
            onSelect={onDomainSelect}
          />
        </div>
      </CardContent>
    </Card>
  );
};
