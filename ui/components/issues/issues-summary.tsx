import {
  CircleHelp,
  Layers,
  type LucideIcon,
  Shield,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import Link from "next/link";

import { CardVariant, ResourceStatsCard } from "@/components/shadcn";
import { issuesHref } from "@/lib/issues/scope";
import { IssuesOverviewAttributes } from "@/types/issues";

interface TileProps {
  value: number;
  label: string;
  detail?: string;
  href: string;
  icon: LucideIcon;
  variant: CardVariant;
}

const Tile = ({ value, label, detail, href, icon, variant }: TileProps) => (
  <Link
    href={href}
    aria-label={[`${value.toLocaleString()} ${label}`, detail]
      .filter(Boolean)
      .join(", ")}
    className="focus-visible:ring-ring/50 min-w-0 rounded-xl focus-visible:ring-2 focus-visible:outline-none"
  >
    <ResourceStatsCard
      badge={{ icon, count: value.toLocaleString(), variant }}
      label={label}
      stats={detail ? [{ icon: ShieldCheck, label: detail }] : []}
      className="hover:border-border-neutral-primary h-full transition-colors"
    />
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
      icon={Layers}
      variant={CardVariant.fail}
    />
    <Tile
      value={summary.issues}
      label="Issues"
      href={issuesHref(scope)}
      icon={Shield}
      variant={CardVariant.default}
    />
    <Tile
      value={summary.actionable}
      label="Exploitable or likely"
      href={issuesHref(scope, { "filter[verdict__in]": "exploitable,likely" })}
      icon={TriangleAlert}
      variant={summary.actionable > 0 ? CardVariant.fail : CardVariant.pass}
    />
    <Tile
      value={summary.not_exploitable}
      label="Not exploitable"
      detail={`${summary.not_exploitable_findings.toLocaleString()} ${summary.not_exploitable_findings === 1 ? "finding" : "findings"} covered by a control`}
      href={issuesHref(scope, { "filter[verdict]": "not_exploitable" })}
      icon={ShieldCheck}
      variant={CardVariant.pass}
    />
    <Tile
      value={summary.unknown}
      label="Unknown"
      href={issuesHref(scope, { "filter[verdict]": "unknown" })}
      icon={CircleHelp}
      variant={CardVariant.warning}
    />
  </div>
);
