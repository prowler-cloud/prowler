import type { AttackSurfaceOverviewResponse } from "@/actions/overview/attack-surface/types";
import type { ComplianceWatchlistResponse } from "@/actions/overview/compliance-watchlist/compliance-watchlist.types";
import type { ResourceGroupOverviewResponse } from "@/actions/overview/resources-inventory/types";
import type { ServicesOverviewResponse } from "@/actions/overview/services/types/services.types";
import type {
  CriticalRequirement,
  SectionScores,
} from "@/actions/overview/threat-score/types/threat-score.types";
import type { LineDataPoint } from "@/components/graphs/types";
import { SEVERITY, type Severity } from "@/types/components";

import {
  SAMPLE_ACCOUNT,
  SAMPLE_CHECKS,
  type SampleCheck,
} from "./sample-dataset";

// Overview payloads derived from SAMPLE_CHECKS. They keep the API response
// shapes, so the page runs them through the same adapters as real data.

const META = { version: "v1" };

const sum = (checks: SampleCheck[], pick: (check: SampleCheck) => number) =>
  checks.reduce((total, check) => total + pick(check), 0);

const groupBy = <K extends string>(
  key: (check: SampleCheck) => K,
): [K, SampleCheck[]][] => {
  const groups: Partial<Record<K, SampleCheck[]>> = {};
  for (const check of SAMPLE_CHECKS) {
    groups[key(check)] = [...(groups[key(check)] ?? []), check];
  }
  return Object.entries(groups) as [K, SampleCheck[]][];
};

const failedBySeverity = (checks: SampleCheck[]): Record<Severity, number> => {
  const counts: Record<Severity, number> = {
    [SEVERITY.CRITICAL]: 0,
    [SEVERITY.HIGH]: 0,
    [SEVERITY.MEDIUM]: 0,
    [SEVERITY.LOW]: 0,
    [SEVERITY.INFORMATIONAL]: 0,
  };
  for (const check of checks) counts[check.severity] += check.failed;
  return counts;
};

// Checks of one service evaluate the same resources; services in a group don't overlap.
const resourcesCount = (checks: SampleCheck[]) => {
  const widestByService: Record<string, number> = {};
  for (const check of checks) {
    widestByService[check.service] = Math.max(
      widestByService[check.service] ?? 0,
      check.failed + check.passed,
    );
  }
  return Object.values(widestByService).reduce((total, n) => total + n, 0);
};

export const SAMPLE_STATUS = {
  fail: sum(SAMPLE_CHECKS, (check) => check.failed),
  pass: sum(SAMPLE_CHECKS, (check) => check.passed),
  failNew: sum(SAMPLE_CHECKS, (check) => check.newFailed),
  passNew: 0,
};

export const SAMPLE_FAILED_BY_SEVERITY = failedBySeverity(SAMPLE_CHECKS);

export const SAMPLE_SERVICES_RESPONSE: ServicesOverviewResponse = {
  data: groupBy((check) => check.service).map(([service, checks]) => ({
    type: "services-overview",
    id: service,
    attributes: {
      total: sum(checks, (check) => check.failed + check.passed),
      fail: sum(checks, (check) => check.failed),
      pass: sum(checks, (check) => check.passed),
      muted: 0,
    },
  })),
  meta: META,
};

export const SAMPLE_RESOURCE_GROUPS_RESPONSE: ResourceGroupOverviewResponse = {
  data: groupBy((check) => check.resourceGroup).map(([group, checks]) => ({
    type: "resource-group-overview",
    id: group,
    attributes: {
      id: group,
      total_findings: sum(checks, (check) => check.failed + check.passed),
      failed_findings: sum(checks, (check) => check.failed),
      new_failed_findings: sum(checks, (check) => check.newFailed),
      resources_count: resourcesCount(checks),
      severity: failedBySeverity(checks),
    },
  })),
  meta: META,
};

export const SAMPLE_ATTACK_SURFACE_RESPONSE: AttackSurfaceOverviewResponse = {
  data: groupBy((check) => check.attackSurface ?? "")
    .filter(([surface]) => surface !== "")
    .map(([surface, checks]) => ({
      type: "attack-surface-overviews",
      id: surface,
      attributes: {
        total_findings: sum(checks, (check) => check.failed + check.passed),
        failed_findings: sum(checks, (check) => check.failed),
        muted_failed_findings: 0,
        check_ids: checks.map((check) => check.checkId),
      },
    })),
  meta: META,
};

const watchlistItem = (
  complianceId: string,
  passed: number,
  failed: number,
  manual: number,
) => ({
  type: "compliance-watchlist-overviews" as const,
  id: complianceId,
  attributes: {
    compliance_id: complianceId,
    requirements_passed: passed,
    requirements_failed: failed,
    requirements_manual: manual,
    total_requirements: passed + failed + manual,
  },
});

export const SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE: ComplianceWatchlistResponse =
  {
    data: [
      watchlistItem("cis_5.0_aws", 38, 21, 4),
      watchlistItem("aws_foundational_security_best_practices_aws", 142, 61, 0),
      watchlistItem("pci_4.0_aws", 97, 52, 12),
      watchlistItem("iso27001_2022_aws", 61, 22, 10),
      watchlistItem("soc2_aws", 44, 13, 6),
    ],
  };

export const SAMPLE_THREAT_SCORE: {
  score: number;
  scoreDelta: number;
  sectionScores: SectionScores;
  criticalRequirements: CriticalRequirement[];
} = {
  score: 61.8,
  scoreDelta: 2.4,
  sectionScores: {
    "1. IAM": 54.2,
    "2. Attack Surface": 58.9,
    "3. Logging and Monitoring": 66.5,
    "4. Encryption": 71.3,
  },
  criticalRequirements: [
    {
      requirement_id: "1.1.1",
      risk_level: 5,
      weight: 1000,
      title: "Ensure MFA is enabled for the root account",
    },
    {
      requirement_id: "2.1.3",
      risk_level: 5,
      weight: 1000,
      title: "Ensure S3 buckets are not publicly accessible",
    },
    {
      requirement_id: "2.2.1",
      risk_level: 5,
      weight: 1000,
      title: "Ensure RDS instances are not publicly accessible",
    },
  ],
};

const TREND_DAYS = 8;
const DAY_MS = 24 * 60 * 60 * 1000;

// A week of daily scans that ends on the sample scan, trending down slowly.
export const SAMPLE_SEVERITY_TRENDS: LineDataPoint[] = Array.from(
  { length: TREND_DAYS },
  (_, index) => {
    const daysAgo = TREND_DAYS - 1 - index;
    const date = new Date(
      Date.parse(SAMPLE_ACCOUNT.scannedAt) - daysAgo * DAY_MS,
    );
    const drift = (severity: Severity) =>
      SAMPLE_FAILED_BY_SEVERITY[severity] + Math.round(daysAgo * 0.6);
    return {
      date: date.toISOString().slice(0, 10),
      critical: drift(SEVERITY.CRITICAL),
      high: drift(SEVERITY.HIGH),
      medium: drift(SEVERITY.MEDIUM),
      low: drift(SEVERITY.LOW),
      informational: SAMPLE_FAILED_BY_SEVERITY[SEVERITY.INFORMATIONAL],
      muted: 0,
      scan_ids: [],
    };
  },
);
