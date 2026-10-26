import {
  CircleHelp,
  Layers,
  Shield,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import Link from "next/link";
import { ReactNode } from "react";

import { Card } from "@/components/shadcn/card/card";
import { issuesHref } from "@/lib/issues/scope";
import { cn } from "@/lib/utils";
import { IssuesOverviewAttributes } from "@/types/issues";

interface TileProps {
  value: number;
  label: string;
  detail?: string;
  href: string;
  icon: ReactNode;
  tone: string;
}

const Tile = ({ value, label, detail, href, icon, tone }: TileProps) => (
  <Link
    href={href}
    aria-label={[`${value.toLocaleString()} ${label}`, detail]
      .filter(Boolean)
      .join(", ")}
    className="focus-visible:ring-ring/50 min-w-0 rounded-xl focus-visible:ring-2 focus-visible:outline-none"
  >
    <Card
      variant="inner"
      padding="md"
      className="hover:border-border-neutral-primary h-full gap-1 transition-colors"
    >
      <span className="flex items-center gap-2">
        <span className={cn("flex items-center gap-1.5", tone)}>
          {icon}
          <span className="text-base leading-none font-semibold tabular-nums">
            {value.toLocaleString()}
          </span>
        </span>
        <span className="text-text-neutral-secondary truncate text-sm">
          {label}
        </span>
      </span>
      {detail && (
        <span className="text-text-neutral-tertiary text-xs">{detail}</span>
      )}
    </Card>
  </Link>
);

/**
 * The reduction, as the first row of the page: findings and issues side by
 * side because the ratio between them is the claim the page makes. Every tile
 * keeps the scope it was counted in.
 */
export const IssuesSummary = ({
  summary,
  scope,
}: {
  summary: IssuesOverviewAttributes;
  /** The filters in force other than the verdict, so the counts still match. */
  scope: Record<string, string>;
}) => (
  <div className="grid grid-cols-2 gap-2 lg:grid-cols-3 2xl:grid-cols-5">
    <Tile
      value={summary.findings}
      label="Failed findings folded"
      href={issuesHref(scope)}
      icon={<Layers className="size-4" aria-hidden="true" />}
      tone="text-text-error-primary"
    />
    <Tile
      value={summary.issues}
      label="Issues"
      href={issuesHref(scope)}
      icon={<Shield className="size-4" aria-hidden="true" />}
      tone="text-text-neutral-primary"
    />
    <Tile
      value={summary.actionable}
      label="Exploitable or likely"
      href={issuesHref(scope, { "filter[verdict__in]": "exploitable,likely" })}
      icon={<TriangleAlert className="size-4" aria-hidden="true" />}
      tone={
        summary.actionable > 0
          ? "text-text-error-primary"
          : "text-text-success-primary"
      }
    />
    <Tile
      value={summary.not_exploitable}
      label="Not exploitable"
      detail={`${summary.not_exploitable_findings.toLocaleString()} ${summary.not_exploitable_findings === 1 ? "finding" : "findings"} covered by a control`}
      href={issuesHref(scope, { "filter[verdict]": "not_exploitable" })}
      icon={<ShieldCheck className="size-4" aria-hidden="true" />}
      tone="text-text-success-primary"
    />
    <Tile
      value={summary.unknown}
      label="Unknown"
      href={issuesHref(scope, { "filter[verdict]": "unknown" })}
      icon={<CircleHelp className="size-4" aria-hidden="true" />}
      tone="text-text-warning-primary"
    />
  </div>
);
