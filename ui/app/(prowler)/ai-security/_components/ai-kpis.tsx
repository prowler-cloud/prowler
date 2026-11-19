import Link from "next/link";
import type { ReactNode } from "react";

import { aiFindingsHref } from "@/app/(prowler)/ai-security/_lib/findings";
import {
  formatScore,
  passScore,
} from "@/app/(prowler)/ai-security/_lib/results";
import type { AiSecurityOverview } from "@/app/(prowler)/ai-security/_types";
import { Button, Card, CardContent } from "@/components/shadcn";
import { cn } from "@/lib/utils";
import {
  SEVERITY_COLORS,
  SEVERITY_DISPLAY_NAMES,
  SEVERITY_LEVELS,
} from "@/types/severities";

import { ResultBar } from "./result-bar";

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

/** The four numbers that say how the AI estate is doing. */
export function AiKpis({ overview }: { overview: AiSecurityOverview }) {
  const { pass, fail, manual, newFailed, fixed, severity } = overview;
  const present = SEVERITY_LEVELS.filter((level) => severity[level] > 0);

  return (
    <section
      aria-label="Key figures"
      className="grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-4"
    >
      <KpiCard label="AI posture" value={formatScore(passScore(overview))}>
        <ResultBar label="AI findings" pass={pass} fail={fail} manual={0} />
        <p className={NOTE}>
          {pass.toLocaleString()} passed, {fail.toLocaleString()} failed. Manual
          results are left out of the score.
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
                <Link href={aiFindingsHref({ "filter[severity__in]": level })}>
                  {severity[level].toLocaleString()}{" "}
                  {SEVERITY_DISPLAY_NAMES[level].toLowerCase()}
                </Link>
              </Button>
            </li>
          ))}
        </ul>
      </KpiCard>

      <KpiCard label="Manual review" value={manual.toLocaleString()}>
        <p className={NOTE}>
          Settings only your policy can judge, like code execution or web search
          in Claude. Each finding shows the value Prowler read.
        </p>
        <div className="mt-auto">
          <Button asChild variant="link" size="link-xs">
            <Link href={aiFindingsHref({ "filter[status__in]": "MANUAL" })}>
              Review settings
            </Link>
          </Button>
        </div>
      </KpiCard>

      <KpiCard
        label="New since the previous scan"
        value={
          <>
            {newFailed.toLocaleString()}{" "}
            <span className="text-text-neutral-tertiary text-sm font-medium">
              new failures
            </span>
          </>
        }
      >
        <p className={NOTE}>
          <span className="text-text-success-primary font-medium">
            {fixed.toLocaleString()} fixed
          </span>{" "}
          since the previous scan.
        </p>
        <div className="mt-auto">
          <Button asChild variant="link" size="link-xs">
            <Link href={aiFindingsHref({ "filter[delta]": "new" })}>
              View new findings
            </Link>
          </Button>
        </div>
      </KpiCard>
    </section>
  );
}
