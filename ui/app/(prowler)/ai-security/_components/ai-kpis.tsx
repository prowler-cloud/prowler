import Link from "next/link";
import type { ReactNode } from "react";

import { aiFindingsHref } from "@/app/(prowler)/ai-security/_lib/findings";
import type { AiSecurityOverview } from "@/app/(prowler)/ai-security/_types";
import { Button, Card, CardContent } from "@/components/shadcn";
import { Progress } from "@/components/shadcn/progress";
import { getScoreColor } from "@/lib/compliance/score-utils";
import { calculatePercentage, cn } from "@/lib/utils";
import {
  SEVERITY_COLORS,
  SEVERITY_DISPLAY_NAMES,
  SEVERITY_LEVELS,
} from "@/types/severities";

interface KpiCardProps {
  label: string;
  value: ReactNode;
  children: ReactNode;
}

function KpiCard({ label, value, children }: KpiCardProps) {
  return (
    <Card variant="base" padding="lg">
      <CardContent className="flex h-full flex-col gap-2">
        <h2 className="text-text-neutral-secondary text-sm font-medium">
          {label}
        </h2>
        <p className="text-text-neutral-primary text-3xl font-semibold tabular-nums">
          {value}
        </p>
        {children}
      </CardContent>
    </Card>
  );
}

const NOTE = "text-text-neutral-tertiary text-xs";

/** The three numbers that say how the AI estate is doing. */
export function AiKpis({
  overview,
  filters,
}: {
  overview: AiSecurityOverview;
  /** The page's scope, carried into the findings links. */
  filters: Record<string, string>;
}) {
  const { pass, fail, newFail, severity } = overview;
  const present = SEVERITY_LEVELS.filter((level) => severity[level] > 0);
  // Pass share of pass and fail findings, as the Overview's Check Findings donut.
  const passRate = calculatePercentage(pass, pass + fail);

  return (
    <section
      aria-label="Key figures"
      className="grid grid-cols-1 gap-6 lg:grid-cols-3"
    >
      <KpiCard label="Pass findings" value={`${passRate}%`}>
        <Progress
          aria-label="Pass findings"
          value={passRate}
          variant={getScoreColor(passRate)}
        />
        <p className={NOTE}>
          {pass.toLocaleString()} pass and {fail.toLocaleString()} fail
          findings.
        </p>
      </KpiCard>

      <KpiCard label="Failed findings" value={fail.toLocaleString()}>
        {fail > 0 && (
          <div
            aria-hidden
            className="bg-bg-neutral-tertiary flex h-2 overflow-hidden rounded-full"
          >
            {present.map((level) => (
              <span
                key={level}
                style={{
                  width: `${(severity[level] / fail) * 100}%`,
                  background: SEVERITY_COLORS[level],
                }}
              />
            ))}
          </div>
        )}
        <ul className={cn(NOTE, "flex flex-wrap gap-x-3 gap-y-1")}>
          {present.map((level) => (
            <li key={level}>
              <Button asChild variant="link" size="link-xs">
                <Link
                  href={aiFindingsHref(filters, {
                    "filter[severity__in]": level,
                  })}
                >
                  {severity[level].toLocaleString()}{" "}
                  {SEVERITY_DISPLAY_NAMES[level].toLowerCase()}
                </Link>
              </Button>
            </li>
          ))}
        </ul>
      </KpiCard>

      <KpiCard label="New failed findings" value={newFail.toLocaleString()}>
        <p className={NOTE}>
          Of {fail.toLocaleString()} failed findings, these were not in the
          previous scan.
        </p>
        {newFail > 0 && (
          <div className="mt-auto">
            <Button asChild variant="link" size="link-xs">
              <Link href={aiFindingsHref(filters, { "filter[delta]": "new" })}>
                View new findings
              </Link>
            </Button>
          </div>
        )}
      </KpiCard>
    </section>
  );
}
