import { describe, expect, it } from "vitest";

import type { CrossProviderComplianceOverviewAttributes } from "@/types/compliance";

import { crossProviderToMapperInput } from "./cross-provider-adapter";

const ATTRIBUTES: CrossProviderComplianceOverviewAttributes = {
  compliance_id: "csa_ccm_4.0",
  framework: "CSA-CCM",
  name: "CSA-CCM",
  version: "4.0",
  description: "Cloud Security Alliance Cloud Controls Matrix",
  compatible_providers: ["aws", "azure", "gcp"],
  requested_providers: ["aws", "azure"],
  providers: ["aws", "azure"],
  scan_ids: ["scan-aws-uuid", "scan-azure-uuid"],
  scan_ids_by_provider: {
    aws: ["scan-aws-uuid"],
    azure: ["scan-azure-uuid"],
  },
  requirements_passed: 1,
  requirements_failed: 1,
  requirements_manual: 0,
  total_requirements: 2,
  requirements: [
    {
      id: "AAA-01",
      name: "Access Control Policy",
      description: "Establish access policies",
      attributes: {
        Section: "Audit & Assurance",
        CCMLite: "Yes",
        IaaS: "Shared",
        PaaS: "Shared",
        SaaS: "Shared",
        ScopeApplicability: [],
      },
      status: "PASS",
      providers: { aws: "PASS", azure: "PASS" },
      check_ids_by_provider: {
        aws: ["aws_check_a", "aws_check_b"],
        azure: ["azure_check_a", "aws_check_a"],
      },
    },
    {
      id: "AAA-02",
      name: "Audit Independence",
      description: "Maintain auditor independence",
      attributes: {
        Section: "Audit & Assurance",
        CCMLite: "No",
        IaaS: "Customer-Owned",
        PaaS: "Customer-Owned",
        SaaS: "Customer-Owned",
        ScopeApplicability: [],
      },
      status: "FAIL",
      providers: { aws: "FAIL" },
      check_ids_by_provider: {
        aws: ["aws_check_c"],
      },
    },
  ],
};

describe("crossProviderToMapperInput", () => {
  it("produces a paired AttributesData / RequirementsData structure", () => {
    const { attributesData, requirementsData } =
      crossProviderToMapperInput(ATTRIBUTES);
    expect(attributesData.data).toHaveLength(2);
    expect(requirementsData.data).toHaveLength(2);
    expect(attributesData.data[0].id).toBe("AAA-01");
    expect(requirementsData.data[0].id).toBe("AAA-01");
  });

  it("wraps the flat attributes dict in a single-element metadata array", () => {
    const { attributesData } = crossProviderToMapperInput(ATTRIBUTES);
    const metadata = attributesData.data[0].attributes.attributes.metadata as {
      Section: string;
    }[];
    expect(metadata).toHaveLength(1);
    expect(metadata[0].Section).toBe("Audit & Assurance");
  });

  it("computes the deduplicated union of check IDs across contributing providers", () => {
    const { attributesData } = crossProviderToMapperInput(ATTRIBUTES);
    const checks = attributesData.data[0].attributes.attributes.check_ids;
    expect(checks).toEqual(
      expect.arrayContaining(["aws_check_a", "aws_check_b", "azure_check_a"]),
    );
    // ``aws_check_a`` appears in both AWS and Azure lists; the union must
    // emit it once so the inner ``Checks`` accordion does not duplicate.
    expect(checks.filter((c) => c === "aws_check_a")).toHaveLength(1);
  });

  it("propagates per-provider context onto the inner attributes slot", () => {
    const { attributesData } = crossProviderToMapperInput(ATTRIBUTES);
    const inner = attributesData.data[0].attributes.attributes;
    expect(inner.providers).toEqual({ aws: "PASS", azure: "PASS" });
    expect(inner.check_ids_by_provider).toEqual({
      aws: ["aws_check_a", "aws_check_b"],
      azure: ["azure_check_a", "aws_check_a"],
    });
    // The scan map is global (shared across all requirements) so the
    // adapter copies it onto every attribute item — that matches how the
    // shared accordion machinery resolves it through ``Requirement``.
    expect(inner.scan_ids_by_provider).toEqual({
      aws: ["scan-aws-uuid"],
      azure: ["scan-azure-uuid"],
    });
  });

  it("preserves the rolled-up requirement status as the input for the per-scan mapper", () => {
    const { requirementsData } = crossProviderToMapperInput(ATTRIBUTES);
    expect(requirementsData.data[0].attributes.status).toBe("PASS");
    expect(requirementsData.data[1].attributes.status).toBe("FAIL");
  });

  it("falls back to empty maps when the API omits the augmentation fields", () => {
    const { attributesData } = crossProviderToMapperInput({
      ...ATTRIBUTES,
      scan_ids_by_provider: {},
      requirements: [
        {
          ...ATTRIBUTES.requirements[0],
          check_ids_by_provider: undefined,
        },
      ],
    });
    const inner = attributesData.data[0].attributes.attributes;
    expect(inner.check_ids).toEqual([]);
    expect(inner.check_ids_by_provider).toEqual({});
    expect(inner.scan_ids_by_provider).toEqual({});
  });
});
