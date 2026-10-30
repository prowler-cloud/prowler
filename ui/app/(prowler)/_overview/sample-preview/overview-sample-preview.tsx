import { type ReactNode } from "react";

import { adaptAttackSurfaceOverview } from "@/actions/overview/attack-surface/attack-surface.adapter";
import { adaptComplianceWatchlistResponse } from "@/actions/overview/compliance-watchlist/compliance-watchlist.adapter";
import { adaptResourceGroupOverview } from "@/actions/overview/resources-inventory/resources-inventory.adapter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { FeatureFlagGate } from "@/components/shared/feature-flag-gate";
import { FEATURE_FLAG } from "@/lib/feature-flags";
import { verdictCounts } from "@/lib/issues/verdicts";
import {
  SAMPLE_ISSUES,
  SAMPLE_ISSUES_OVERVIEW,
} from "@/lib/sample-preview/sample-issues";
import {
  SAMPLE_ATTACK_SURFACE_RESPONSE,
  SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE,
  SAMPLE_FAILED_BY_SEVERITY,
  SAMPLE_RESOURCE_GROUPS_RESPONSE,
  SAMPLE_SERVICES_RESPONSE,
  SAMPLE_SEVERITY_TRENDS,
  SAMPLE_STATUS,
  SAMPLE_THREAT_SCORE,
} from "@/lib/sample-preview/sample-overview";

import { OverviewGrid } from "../_components/overview-grid";
import { AttackSurface } from "../attack-surface/_components/attack-surface";
import { ExploitabilityChart } from "../exploitability";
import { TopIssues } from "../exploitability/_components/top-issues";
import { ResourcesInventory } from "../resources-inventory/_components/resources-inventory";
import { RiskSeverityChart } from "../risk-severity";
import { FindingSeverityOverTime } from "../severity-over-time";
import { StatusChart } from "../status-chart";
import { ThreatScore } from "../threat-score";
import { ComplianceWatchlist, ServiceWatchlist } from "../watchlist";

import { SampleGraphsTabs } from "./sample-graphs-tabs";

// `contents` keeps each card a direct item of the grid's flex rows, while
// `inert` stops links and drill-downs into data the tenant does not have.
const Inert = ({ children }: { children: ReactNode }) => (
  <div inert className="contents">
    {children}
  </div>
);

const NO_SCOPE: Record<string, string> = {};

interface OverviewSamplePreviewProps {
  // Exploitability and Top issues only exist in Prowler Cloud, behind their flag.
  showIssues: boolean;
}

/** The Overview filled with the demo account, for tenants without a scan. */
export function OverviewSamplePreview({
  showIssues,
}: OverviewSamplePreviewProps) {
  const complianceItems = adaptComplianceWatchlistResponse(
    SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE,
  ).map((item) => ({
    id: item.id,
    framework: item.complianceId,
    label: item.label,
    icon: item.icon,
    score: item.score,
  }));

  return (
    <OverviewGrid
      threatScore={
        <Inert>
          <ThreatScore
            score={SAMPLE_THREAT_SCORE.score}
            scoreDelta={SAMPLE_THREAT_SCORE.scoreDelta}
            sectionScores={SAMPLE_THREAT_SCORE.sectionScores}
            criticalRequirements={SAMPLE_THREAT_SCORE.criticalRequirements}
          />
        </Inert>
      }
      exploitability={
        showIssues ? (
          <FeatureFlagGate flag={FEATURE_FLAG.ISSUES}>
            <Inert>
              <ExploitabilityChart
                counts={verdictCounts(SAMPLE_ISSUES_OVERVIEW)}
                issues={SAMPLE_ISSUES_OVERVIEW.issues}
                findings={SAMPLE_ISSUES_OVERVIEW.findings}
                actionable={SAMPLE_ISSUES_OVERVIEW.actionable}
                coveredFindings={
                  SAMPLE_ISSUES_OVERVIEW.not_exploitable_findings
                }
                scope={NO_SCOPE}
              />
            </Inert>
          </FeatureFlagGate>
        ) : undefined
      }
      checkFindings={
        <Inert>
          <StatusChart
            failFindingsData={{
              total: SAMPLE_STATUS.fail,
              new: SAMPLE_STATUS.failNew,
            }}
            passFindingsData={{
              total: SAMPLE_STATUS.pass,
              new: SAMPLE_STATUS.passNew,
            }}
          />
        </Inert>
      }
      riskSeverity={
        <Inert>
          <RiskSeverityChart {...SAMPLE_FAILED_BY_SEVERITY} />
        </Inert>
      }
      resourcesInventory={
        <Inert>
          <ResourcesInventory
            items={adaptResourceGroupOverview(SAMPLE_RESOURCE_GROUPS_RESPONSE)}
          />
        </Inert>
      }
      complianceWatchlist={
        <Inert>
          <ComplianceWatchlist items={complianceItems} hasWatchlist />
        </Inert>
      }
      serviceWatchlist={
        <Inert>
          <ServiceWatchlist items={SAMPLE_SERVICES_RESPONSE.data} />
        </Inert>
      }
      attackSurface={
        <Inert>
          <AttackSurface
            items={adaptAttackSurfaceOverview(SAMPLE_ATTACK_SURFACE_RESPONSE)}
          />
        </Inert>
      }
      topIssues={
        showIssues ? (
          <FeatureFlagGate flag={FEATURE_FLAG.ISSUES}>
            <Inert>
              <TopIssues issues={SAMPLE_ISSUES} scope={NO_SCOPE} />
            </Inert>
          </FeatureFlagGate>
        ) : undefined
      }
      severityOverTime={
        <Inert>
          <Card variant="base" className="flex h-full flex-1 flex-col">
            <CardHeader className="flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <CardTitle>Findings Severity Over Time</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="flex flex-1 flex-col px-6">
              <FindingSeverityOverTime data={SAMPLE_SEVERITY_TRENDS} />
            </CardContent>
          </Card>
        </Inert>
      }
      graphsTabs={<SampleGraphsTabs />}
    />
  );
}
