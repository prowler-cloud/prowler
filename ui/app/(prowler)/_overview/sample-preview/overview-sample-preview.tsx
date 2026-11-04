import { adaptAttackSurfaceOverview } from "@/actions/overview/attack-surface/attack-surface.adapter";
import { adaptComplianceWatchlistResponse } from "@/actions/overview/compliance-watchlist/compliance-watchlist.adapter";
import type { ComplianceWatchlistResponse } from "@/actions/overview/compliance-watchlist/compliance-watchlist.types";
import { adaptResourceGroupOverview } from "@/actions/overview/resources-inventory/resources-inventory.adapter";
import { FindingSeverityOverTimeCard } from "@/components/overview/finding-severity-over-time-card";
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

const NO_SCOPE: Record<string, string> = {};

interface OverviewSamplePreviewProps {
  // Exploitability and Top issues only exist in Prowler Cloud, behind their flag.
  showIssues: boolean;
  /** Compliance totals derived from the sample requirements, when available. */
  complianceWatchlist?: ComplianceWatchlistResponse["data"];
}

/** The Overview filled with the demo account, for tenants without a scan. */
export function OverviewSamplePreview({
  showIssues,
  complianceWatchlist = SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE.data,
}: OverviewSamplePreviewProps) {
  const complianceItems = adaptComplianceWatchlistResponse({
    ...SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE,
    data: complianceWatchlist,
  }).map((item) => ({
    id: item.id,
    framework: item.complianceId,
    label: item.label,
    icon: item.icon,
    score: item.score,
  }));

  return (
    <OverviewGrid
      threatScore={
        <ThreatScore
          score={SAMPLE_THREAT_SCORE.score}
          scoreDelta={SAMPLE_THREAT_SCORE.scoreDelta}
          sectionScores={SAMPLE_THREAT_SCORE.sectionScores}
          criticalRequirements={SAMPLE_THREAT_SCORE.criticalRequirements}
        />
      }
      exploitability={
        showIssues ? (
          <ExploitabilityChart
            counts={verdictCounts(SAMPLE_ISSUES_OVERVIEW)}
            issues={SAMPLE_ISSUES_OVERVIEW.issues}
            findings={SAMPLE_ISSUES_OVERVIEW.findings}
            actionable={SAMPLE_ISSUES_OVERVIEW.actionable}
            coveredFindings={SAMPLE_ISSUES_OVERVIEW.not_exploitable_findings}
            scope={NO_SCOPE}
          />
        ) : undefined
      }
      checkFindings={
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
      }
      riskSeverity={<RiskSeverityChart {...SAMPLE_FAILED_BY_SEVERITY} />}
      resourcesInventory={
        <ResourcesInventory
          items={adaptResourceGroupOverview(SAMPLE_RESOURCE_GROUPS_RESPONSE)}
        />
      }
      complianceWatchlist={
        // The sample Compliance page is per scan: no multi-scan view to link.
        <ComplianceWatchlist items={complianceItems} hasWatchlist={false} />
      }
      serviceWatchlist={
        <ServiceWatchlist items={SAMPLE_SERVICES_RESPONSE.data} />
      }
      attackSurface={
        <AttackSurface
          items={adaptAttackSurfaceOverview(SAMPLE_ATTACK_SURFACE_RESPONSE)}
        />
      }
      topIssues={
        showIssues ? (
          <TopIssues issues={SAMPLE_ISSUES} scope={NO_SCOPE} />
        ) : undefined
      }
      severityOverTime={
        <FindingSeverityOverTimeCard>
          <FindingSeverityOverTime data={SAMPLE_SEVERITY_TRENDS} readOnly />
        </FindingSeverityOverTimeCard>
      }
      graphsTabs={<SampleGraphsTabs />}
    />
  );
}
