import Link from "next/link";

import { aiFindingsHref } from "@/app/(prowler)/ai-security/_lib/findings";
import type { AiTopRisk } from "@/app/(prowler)/ai-security/_types";
import { Button, Card, CardContent } from "@/components/shadcn";
import { SeverityBadge } from "@/components/shadcn/table/severity-badge";

import { SectionHeader } from "./section-header";

/** The failed AI checks to fix first, each linking to its findings. */
export const TopRisks = ({
  risks,
  filters,
}: {
  risks: AiTopRisk[];
  /** The page's scope, carried into the findings links. */
  filters: Record<string, string>;
}) => (
  <Card variant="base" className="w-full min-w-0">
    <SectionHeader
      title="Top risks"
      description="Failed checks, ranked as on Findings: by severity, then new and changed failures."
      aside={
        <Button asChild variant="link" size="link-sm">
          <Link href={aiFindingsHref(filters)}>View all AI findings</Link>
        </Button>
      }
    />
    <CardContent>
      {risks.length > 0 ? (
        <ul className="divide-border-neutral-secondary flex flex-col divide-y">
          {risks.map((risk) => (
            <li
              key={risk.checkId}
              className="flex flex-wrap items-center gap-x-4 gap-y-1 py-3"
            >
              <div className="w-20 shrink-0">
                <SeverityBadge severity={risk.severity} />
              </div>
              <div className="flex min-w-0 flex-1 basis-64 flex-col">
                <div className="flex max-w-full">
                  <Button
                    asChild
                    variant="link"
                    size="link-sm"
                    className="min-w-0 shrink"
                  >
                    <Link
                      href={aiFindingsHref(filters, {
                        "filter[check_id__in]": risk.checkId,
                      })}
                      title={risk.title}
                    >
                      <span className="truncate">{risk.title}</span>
                    </Link>
                  </Button>
                </div>
                <span className="text-text-neutral-tertiary truncate font-mono text-xs">
                  {risk.checkId}
                </span>
              </div>
              <span className="text-text-neutral-secondary w-20 shrink-0 text-xs">
                {risk.providerName}
              </span>
              <span className="text-text-neutral-secondary w-28 shrink-0 text-right text-xs">
                {risk.affected}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-text-neutral-tertiary py-8 text-center text-sm">
          No failed AI findings in this scope.
        </p>
      )}
    </CardContent>
  </Card>
);
