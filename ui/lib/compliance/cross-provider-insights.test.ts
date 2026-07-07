import { describe, expect, it } from "vitest";

import type { CrossProviderComplianceOverviewAttributes } from "@/types/compliance";

import { computeCrossProviderInsights } from "./cross-provider-insights";

const buildAttributes = (): CrossProviderComplianceOverviewAttributes => ({
  compliance_id: "csa_ccm_4.0",
  framework: "CSA-CCM",
  name: "CSA-CCM",
  version: "4.0",
  description: "test",
  compatible_providers: ["aws", "azure", "gcp"],
  requested_providers: ["aws", "azure", "gcp"],
  providers: ["aws", "azure"],
  scan_ids: ["scan-aws", "scan-azure", "scan-gcp"],
  scan_ids_by_provider: {
    aws: ["scan-aws"],
    azure: ["scan-azure"],
    gcp: ["scan-gcp"],
  },
  requirements_passed: 2,
  requirements_failed: 2,
  requirements_manual: 1,
  total_requirements: 5,
  requirements: [
    {
      id: "AAA-01",
      name: "A",
      description: "",
      attributes: { Section: "Audit" },
      status: "PASS",
      providers: { aws: "PASS", azure: "PASS" },
    },
    {
      id: "AAA-02",
      name: "B",
      description: "",
      attributes: { Section: "Audit" },
      status: "FAIL",
      providers: { aws: "FAIL", azure: "PASS" },
    },
    {
      id: "DSP-01",
      name: "C",
      description: "",
      attributes: { Section: "Data Sec" },
      status: "FAIL",
      providers: { aws: "FAIL" },
    },
    {
      id: "DSP-02",
      name: "D",
      description: "",
      attributes: { Section: "Data Sec" },
      status: "MANUAL",
      providers: {},
    },
    {
      id: "OTHER-01",
      name: "E",
      description: "",
      // No Section attribute — must land in the ``Other`` bucket.
      attributes: {},
      status: "PASS",
      providers: { aws: "PASS" },
    },
  ],
});

describe("computeCrossProviderInsights", () => {
  it("computes the score from passed/total", () => {
    const insights = computeCrossProviderInsights(buildAttributes());
    // 2 / 5 = 40
    expect(insights.scorePercent).toBe(40);
    expect(insights.pass).toBe(2);
    expect(insights.fail).toBe(2);
    expect(insights.manual).toBe(1);
    expect(insights.total).toBe(5);
  });

  it("builds providerCoverage for every scanned provider, contributing or not", () => {
    const insights = computeCrossProviderInsights(buildAttributes());
    const byKey = Object.fromEntries(
      insights.providerCoverage.map((c) => [c.key, c]),
    );
    expect(byKey.aws.contributing).toBe(true);
    expect(byKey.aws.scanIds).toEqual(["scan-aws"]);
    expect(byKey.aws.accountCount).toBe(1);
    // AWS contributed 4 rows: 2 PASS + 2 FAIL.
    expect(byKey.aws.pass).toBe(2);
    expect(byKey.aws.fail).toBe(2);
    expect(byKey.aws.total).toBe(4);
    expect(byKey.aws.scorePercent).toBe(50);

    // Azure contributed 2 rows: both PASS → 100%.
    expect(byKey.azure.contributing).toBe(true);
    expect(byKey.azure.pass).toBe(2);
    expect(byKey.azure.total).toBe(2);
    expect(byKey.azure.scorePercent).toBe(100);

    // GCP HAS a scan (it's in scan_ids_by_provider) but the API marks it
    // non-contributing (no requirement row) — it still surfaces (scanned),
    // with zeroed counts so the panel can dim it.
    expect(byKey.gcp.contributing).toBe(false);
    expect(byKey.gcp.total).toBe(0);
    expect(byKey.gcp.scorePercent).toBe(0);
  });

  it("shows only scanned providers in the detail (hides compatible providers with no scan)", () => {
    const noGcpScan: CrossProviderComplianceOverviewAttributes = {
      ...buildAttributes(),
      // gcp stays compatible but is NOT scanned (dropped from scan_ids_by_provider).
      providers: ["aws", "azure"],
      scan_ids_by_provider: { aws: ["scan-aws"], azure: ["scan-azure"] },
      scan_ids: ["scan-aws", "scan-azure"],
    };
    const insights = computeCrossProviderInsights(noGcpScan);

    // Detail surfaces (coverage panel, heatmap columns) only include scanned.
    expect(insights.scannedProviders).toEqual(["aws", "azure"]);
    expect(insights.providerCoverage.map((c) => c.key)).toEqual([
      "aws",
      "azure",
    ]);
    for (const domain of insights.domainStats) {
      expect(Object.keys(domain.byProvider)).not.toContain("gcp");
    }

    // ...but the full compatible set is still reported (the overview uses it).
    expect(insights.compatibleProviders).toContain("gcp");
  });

  it("aggregates per-domain stats by Section attribute, with an Other bucket fallback", () => {
    const insights = computeCrossProviderInsights(buildAttributes());
    const byName = Object.fromEntries(
      insights.domainStats.map((d) => [d.name, d]),
    );
    expect(Object.keys(byName).sort()).toEqual(["Audit", "Data Sec", "Other"]);
    expect(byName.Audit.total).toBe(2);
    expect(byName.Audit.pass).toBe(1);
    expect(byName.Audit.fail).toBe(1);
    expect(byName["Data Sec"].fail).toBe(1);
    expect(byName["Data Sec"].manual).toBe(1);
    // Section-less requirements must not silently disappear.
    expect(byName.Other.total).toBe(1);
  });

  it("groups DORA-shaped requirements (Pillar, no Section) by Pillar — not Other", () => {
    // DORA's universal JSON carries Pillar/Article/ArticleTitle only. The
    // domain key must match the DORA mapper's ``categoryName`` (the Pillar)
    // or the accordion's per-section stats lookup never hits.
    const doraAttributes: CrossProviderComplianceOverviewAttributes = {
      ...buildAttributes(),
      compliance_id: "dora_2022_2554",
      framework: "DORA",
      name: "DORA",
      requirements: [
        {
          id: "art5",
          name: "Governance",
          description: "",
          attributes: {
            Pillar: "ICT Risk Management",
            Article: "Article 5",
            ArticleTitle: "Governance and organisation",
          },
          status: "FAIL",
          providers: { aws: "FAIL" },
        },
        {
          id: "art9",
          name: "Protection",
          description: "",
          attributes: {
            Pillar: "ICT Risk Management",
            Article: "Article 9",
            ArticleTitle: "Protection and prevention",
          },
          status: "PASS",
          providers: { aws: "PASS" },
        },
        {
          id: "art17",
          name: "Incidents",
          description: "",
          attributes: {
            Pillar: "ICT Incident Management",
            Article: "Article 17",
            ArticleTitle: "ICT-related incident management process",
          },
          status: "MANUAL",
          providers: {},
        },
      ],
    };
    const insights = computeCrossProviderInsights(doraAttributes);
    const names = insights.domainStats.map((d) => d.name).sort();
    expect(names).toEqual(["ICT Incident Management", "ICT Risk Management"]);
    expect(names).not.toContain("Other");

    const riskMgmt = insights.domainStats.find(
      (d) => d.name === "ICT Risk Management",
    );
    expect(riskMgmt?.total).toBe(2);
    expect(riskMgmt?.fail).toBe(1);
    expect(riskMgmt?.pass).toBe(1);
    expect(riskMgmt?.byProvider.aws).toBe("FAIL");
  });

  it("falls back to Other for non-string or empty Section/Pillar values", () => {
    const weird: CrossProviderComplianceOverviewAttributes = {
      ...buildAttributes(),
      requirements: [
        {
          id: "w1",
          name: "numeric section",
          description: "",
          attributes: { Section: 3 },
          status: "PASS",
          providers: { aws: "PASS" },
        },
        {
          id: "w2",
          name: "empty pillar",
          description: "",
          attributes: { Pillar: "" },
          status: "FAIL",
          providers: { aws: "FAIL" },
        },
      ],
    };
    const insights = computeCrossProviderInsights(weird);
    expect(insights.domainStats.map((d) => d.name)).toEqual(["Other"]);
    expect(insights.domainStats[0].total).toBe(2);
  });

  it("rolls each domain's per-provider status with FAIL > PASS > MANUAL > NO_ROW", () => {
    const insights = computeCrossProviderInsights(buildAttributes());
    const audit = insights.domainStats.find((d) => d.name === "Audit");
    if (!audit) throw new Error("Audit domain missing");
    // AWS contributed PASS + FAIL → FAIL.
    expect(audit.byProvider.aws).toBe("FAIL");
    // Azure contributed PASS + PASS → PASS.
    expect(audit.byProvider.azure).toBe("PASS");
    // GCP did not contribute any row in the Audit domain.
    expect(audit.byProvider.gcp).toBe("NO_ROW");

    const dataSec = insights.domainStats.find((d) => d.name === "Data Sec");
    if (!dataSec) throw new Error("Data Sec missing");
    expect(dataSec.byProvider.aws).toBe("FAIL");
    expect(dataSec.byProvider.azure).toBe("NO_ROW");
  });

  it("orders domainsByFailCount descending", () => {
    const insights = computeCrossProviderInsights(buildAttributes());
    expect(insights.domainsByFailCount.map((d) => d.name)).toEqual([
      "Audit",
      "Data Sec",
      "Other",
    ]);
    expect(insights.domainsByFailCount[0].fail).toBeGreaterThanOrEqual(
      insights.domainsByFailCount[1].fail,
    );
  });

  it("surfaces accountCount > 1 when a provider type has N accounts", () => {
    const multiAccount: CrossProviderComplianceOverviewAttributes = {
      ...buildAttributes(),
      // Same provider type, two distinct scan UUIDs (= two accounts).
      scan_ids_by_provider: {
        aws: ["scan-aws-prod", "scan-aws-dev"],
        azure: ["scan-azure"],
        gcp: ["scan-gcp"],
      },
      scan_ids: ["scan-aws-prod", "scan-aws-dev", "scan-azure", "scan-gcp"],
    };
    const insights = computeCrossProviderInsights(multiAccount);
    const aws = insights.providerCoverage.find((c) => c.key === "aws");
    if (!aws) throw new Error("aws coverage missing");
    expect(aws.scanIds).toEqual(["scan-aws-prod", "scan-aws-dev"]);
    expect(aws.accountCount).toBe(2);
  });

  it("returns a stable zero-state when total_requirements is 0", () => {
    const empty: CrossProviderComplianceOverviewAttributes = {
      ...buildAttributes(),
      requirements: [],
      requirements_passed: 0,
      requirements_failed: 0,
      requirements_manual: 0,
      total_requirements: 0,
      providers: [],
    };
    const insights = computeCrossProviderInsights(empty);
    expect(insights.scorePercent).toBe(0);
    expect(insights.domainStats).toEqual([]);
    expect(insights.domainsByFailCount).toEqual([]);
    // Scanned providers still surface (empty stats) so the coverage
    // panel doesn't disappear.
    expect(insights.providerCoverage).toHaveLength(3);
  });
});
