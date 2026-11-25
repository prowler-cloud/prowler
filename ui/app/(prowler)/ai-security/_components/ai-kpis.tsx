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

/** The four numbers that say how the AI estate is doing. */
export function AiKpis({ overview }: { overview: AiSecurityOverview }) {
  const { pass, fail, manual, severity, layers } = overview;
  const providers = layers.flatMap((layer) => layer.providers);
  const connected = providers.filter((provider) => provider.connected);
  const present = SEVERITY_LEVELS.filter((level) => severity[level] > 0);
  // Pass share of pass and fail findings, as the Overview's Check Findings donut.
  const passRate = calculatePercentage(pass, pass + fail);

  return (
    <section
      aria-label="Key figures"
      className="grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-4"
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

      <KpiCard label="AI providers" value={connected.length.toLocaleString()}>
        <p className={NOTE}>
          {connected.map((provider) => provider.name).join(", ")} connected, out
          of {providers.length} AI provider types.
        </p>
        <div className="mt-auto">
          <Button asChild variant="link" size="link-xs">
            <Link href="/providers">Manage providers</Link>
          </Button>
        </div>
      </KpiCard>
    </section>
  );
}
