import {
  COMPLIANCE_OVERVIEW_TYPE,
  ComplianceOverviewData,
} from "@/types/compliance";
import type { ScanEntity } from "@/types/scans";

import { SAMPLE_ACCOUNT } from "./sample-dataset";
import { SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE } from "./sample-overview";

// The Overview watchlist frameworks as per-scan compliance overviews, so both
// pages show the same requirement counts.

// Framework and version as the compliance-overviews API names them.
const SAMPLE_FRAMEWORK_NAMES: Record<
  string,
  { framework: string; version: string }
> = {
  "cis_5.0_aws": { framework: "CIS", version: "5.0" },
  aws_foundational_security_best_practices_aws: {
    framework: "AWS-Foundational-Security-Best-Practices",
    version: "",
  },
  "pci_4.0_aws": { framework: "PCI-DSS", version: "4.0" },
  iso27001_2022_aws: { framework: "ISO27001", version: "2022" },
  soc2_aws: { framework: "SOC2", version: "" },
};

export const SAMPLE_COMPLIANCE_OVERVIEWS: ComplianceOverviewData[] =
  SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE.data.map(({ attributes }) => ({
    type: COMPLIANCE_OVERVIEW_TYPE.OVERVIEW,
    id: attributes.compliance_id,
    attributes: {
      framework:
        SAMPLE_FRAMEWORK_NAMES[attributes.compliance_id]?.framework ??
        attributes.compliance_id,
      version: SAMPLE_FRAMEWORK_NAMES[attributes.compliance_id]?.version ?? "",
      requirements_passed: attributes.requirements_passed,
      requirements_failed: attributes.requirements_failed,
      requirements_manual: attributes.requirements_manual,
      total_requirements: attributes.total_requirements,
    },
  }));

export const SAMPLE_SCAN: ScanEntity = {
  id: SAMPLE_ACCOUNT.scanId,
  providerInfo: {
    provider: "aws",
    alias: SAMPLE_ACCOUNT.alias,
    uid: SAMPLE_ACCOUNT.uid,
  },
  attributes: { name: "Sample scan", completed_at: SAMPLE_ACCOUNT.scannedAt },
};
