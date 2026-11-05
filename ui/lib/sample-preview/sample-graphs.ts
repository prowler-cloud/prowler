import {
  adaptToSankeyData,
  type SankeyData,
} from "@/actions/overview/providers/sankey.adapter";
import {
  adaptRegionsOverviewToThreatMap,
  type ThreatMapData,
} from "@/actions/overview/regions/threat-map.adapter";
import type { RegionsOverviewResponse } from "@/actions/overview/regions/types";
import { adaptToRiskPlotData } from "@/actions/overview/risk-plot/risk-plot.adapter";
import type { RiskPlotPoint } from "@/actions/overview/risk-plot/types/risk-plot.types";
import { adaptCategoryOverviewToRadarData } from "@/actions/overview/risk-radar/risk-radar.adapter";
import type { CategoryOverviewResponse } from "@/actions/overview/risk-radar/types";
import type { RadarDataPoint } from "@/components/graphs/types";
import { type FindingProps, SEVERITY } from "@/types/components";

import {
  SAMPLE_ACCOUNT,
  SAMPLE_CHECKS,
  SAMPLE_REGIONS,
  type SampleCheck,
} from "./sample-dataset";
import {
  SAMPLE_FAILED_BY_SEVERITY,
  SAMPLE_THREAT_SCORE,
} from "./sample-overview";
import { SAMPLE_FINDINGS, sampleExpandedFindings } from "./sample-records";

// Graphs-tab payloads derived from SAMPLE_CHECKS, run through the real adapters.

const META = { version: "v1" };
const PROVIDER_TYPE = "aws";
const NEW_FINDINGS_LIMIT = 10;

// Splits a count across SAMPLE_REGIONS; the remainder starts at `offset`.
const splitAcrossRegions = (count: number, offset: number): number[] =>
  SAMPLE_REGIONS.map((_, regionIndex) => {
    const base = Math.floor(count / SAMPLE_REGIONS.length);
    const slot =
      (((regionIndex - offset) % SAMPLE_REGIONS.length) +
        SAMPLE_REGIONS.length) %
      SAMPLE_REGIONS.length;
    return base + (slot < count % SAMPLE_REGIONS.length ? 1 : 0);
  });

export const SAMPLE_SANKEY_DATA: SankeyData = adaptToSankeyData({
  [PROVIDER_TYPE]: SAMPLE_FAILED_BY_SEVERITY,
});

const SAMPLE_REGIONS_RESPONSE: RegionsOverviewResponse = {
  data: SAMPLE_REGIONS.map((region, regionIndex) => {
    let fail = 0;
    let pass = 0;
    SAMPLE_CHECKS.forEach((check, checkIndex) => {
      fail += splitAcrossRegions(check.failed, checkIndex)[regionIndex];
      pass += splitAcrossRegions(check.passed, checkIndex)[regionIndex];
    });
    return {
      type: "regions-overview" as const,
      id: `${PROVIDER_TYPE}-${region}`,
      attributes: {
        provider_type: PROVIDER_TYPE,
        region,
        total: fail + pass,
        fail,
        pass,
        muted: 0,
      },
    };
  }),
  meta: META,
};

export const SAMPLE_THREAT_MAP_DATA: ThreatMapData =
  adaptRegionsOverviewToThreatMap(SAMPLE_REGIONS_RESPONSE);

export const SAMPLE_RISK_PLOT_POINTS: RiskPlotPoint[] = adaptToRiskPlotData([
  {
    providerId: SAMPLE_ACCOUNT.providerId,
    providerType: PROVIDER_TYPE,
    providerName: SAMPLE_ACCOUNT.alias,
    overallScore: SAMPLE_THREAT_SCORE.score,
    failedFindings: Object.values(SAMPLE_FAILED_BY_SEVERITY).reduce(
      (total, count) => total + count,
      0,
    ),
    severity: SAMPLE_FAILED_BY_SEVERITY,
  },
]).points;

// Prowler check-metadata categories for the sample checks.
const CATEGORIES_BY_CHECK: Record<string, string[]> = {
  s3_bucket_public_access: ["internet-exposed"],
  iam_root_mfa_enabled: ["identity-access"],
  rds_instance_no_public_access: ["internet-exposed"],
  awslambda_function_no_secrets_in_variables: ["secrets"],
  ec2_instance_secrets_user_data: ["secrets"],
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22: [
    "internet-exposed",
  ],
  iam_policy_allows_privilege_escalation: ["identity-access"],
  cloudtrail_multi_region_enabled: ["logging", "forensics-ready"],
  iam_user_mfa_enabled_console_access: ["identity-access"],
  eks_cluster_not_publicly_accessible: ["internet-exposed"],
  ec2_instance_imdsv2_enabled: ["ec2-imdsv1"],
  ec2_ebs_volume_encryption: ["encryption"],
  s3_bucket_secure_transport_policy: ["encryption"],
  iam_rotate_access_key_90_days: ["identity-access"],
  guardduty_is_enabled: ["threat-detection"],
  config_recorder_all_regions_enabled: ["logging", "forensics-ready"],
  vpc_flow_logs_enabled: ["logging", "forensics-ready"],
  kms_cmk_rotation_enabled: ["encryption"],
  apigateway_restapi_logging_enabled: ["logging"],
  sqs_queues_server_side_encryption_enabled: ["encryption"],
  cloudwatch_log_metric_filter_root_usage: ["logging"],
  ec2_instance_managed_by_ssm: ["node-security"],
};

const categoriesOf = (check: SampleCheck) =>
  CATEGORIES_BY_CHECK[check.checkId] ?? [];

const SAMPLE_CATEGORIES_RESPONSE: CategoryOverviewResponse = {
  data: Array.from(new Set(SAMPLE_CHECKS.flatMap(categoriesOf))).map(
    (category) => {
      const checks = SAMPLE_CHECKS.filter((check) =>
        categoriesOf(check).includes(category),
      );
      const severity = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
      };
      for (const check of checks) severity[check.severity] += check.failed;
      return {
        type: "category-overviews" as const,
        id: category,
        attributes: {
          total_findings: checks.reduce(
            (total, check) => total + check.failed + check.passed,
            0,
          ),
          failed_findings: checks.reduce(
            (total, check) => total + check.failed,
            0,
          ),
          new_failed_findings: checks.reduce(
            (total, check) => total + check.newFailed,
            0,
          ),
          severity,
        },
      };
    },
  ),
  meta: META,
};

export const SAMPLE_RADAR_DATA: RadarDataPoint[] =
  adaptCategoryOverviewToRadarData(SAMPLE_CATEGORIES_RESPONSE);

const SEVERITY_RANK = [
  SEVERITY.CRITICAL,
  SEVERITY.HIGH,
  SEVERITY.MEDIUM,
  SEVERITY.LOW,
  SEVERITY.INFORMATIONAL,
];

// Latest new failed findings, most severe first, like the real tab. They are
// the sample records, so a row opens the same finding the drawer resolves.
export const SAMPLE_NEW_FINDINGS = sampleExpandedFindings(
  SAMPLE_FINDINGS.filter(
    (finding) => finding.status === "FAIL" && finding.delta === "new",
  )
    .sort(
      (a, b) =>
        SEVERITY_RANK.indexOf(a.check.severity) -
        SEVERITY_RANK.indexOf(b.check.severity),
    )
    .slice(0, NEW_FINDINGS_LIMIT),
) as unknown as FindingProps[];
