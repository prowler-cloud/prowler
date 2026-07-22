import { describe, expect, it } from "vitest";

import type { CrossAccountOverviewAttributes } from "../../_types";
import {
  accountDisplayLabel,
  buildAccountExtrasMap,
  computeAccountBreakdown,
  crossAccountToMapperInput,
} from "../cross-account-adapter";

const ACC1 = "11111111-1111-4111-8111-111111111111";
const ACC2 = "22222222-2222-4222-8222-222222222222";

const buildAttrs = (): CrossAccountOverviewAttributes => ({
  compliance_id: "cis_2.0_aws",
  provider_type: "aws",
  framework: "CIS",
  name: "CIS Amazon Web Services Foundations Benchmark",
  version: "2.0",
  description: "CIS AWS 2.0",
  accounts: [
    { id: ACC1, uid: "123456789012", alias: "prod" },
    { id: ACC2, uid: "210987654321", alias: null },
  ],
  scan_ids: ["scan-1", "scan-2"],
  scan_ids_by_account: { [ACC1]: ["scan-1"], [ACC2]: ["scan-2"] },
  requirements_passed: 1,
  requirements_failed: 1,
  requirements_manual: 0,
  total_requirements: 2,
  requirements: [
    {
      id: "1.1",
      name: "Maintain current contact details",
      description: "desc-1",
      attributes: [{ Section: "1. IAM" }],
      status: "FAIL",
      accounts: { [ACC1]: "FAIL", [ACC2]: "PASS" },
      check_ids: ["account_maintain_current_contact_details"],
    },
    {
      id: "1.2",
      name: "",
      description: "desc-2",
      attributes: [],
      status: "PASS",
      accounts: { [ACC1]: "PASS" },
      check_ids: [],
    },
  ],
});

describe("crossAccountToMapperInput", () => {
  it("produces the mapper pair with flat check_ids and passthrough metadata", () => {
    const { attributesData, requirementsData } =
      crossAccountToMapperInput(buildAttrs());

    expect(attributesData.data).toHaveLength(2);
    expect(requirementsData.data).toHaveLength(2);

    const first = attributesData.data[0];
    expect(first.id).toBe("1.1");
    expect(first.attributes.framework).toBe("CIS");
    // The per-provider template already ships metadata as a list — it must
    // feed attributes.metadata directly, not get re-wrapped.
    expect(first.attributes.attributes.metadata).toEqual([
      { Section: "1. IAM" },
    ]);
    expect(first.attributes.attributes.check_ids).toEqual([
      "account_maintain_current_contact_details",
    ]);

    expect(requirementsData.data[0].attributes.status).toBe("FAIL");
    expect(requirementsData.data[1].attributes.status).toBe("PASS");
  });
});

describe("buildAccountExtrasMap", () => {
  it("registers every candidate name a framework mapper may compose", () => {
    const extras = buildAccountExtrasMap(buildAttrs());

    // CSA/CIS-Controls/DORA-style mappers compose "id - name"; CIS/CCC/PCI
    // use the bare id; the generic mapper uses the bare name. All three
    // must resolve to the same entry so the accordion join works for every
    // framework the cross-account view serves.
    const composed = extras.get("1.1 - Maintain current contact details");
    expect(composed).toBeDefined();
    expect(extras.get("1.1")).toBe(composed);
    expect(extras.get("Maintain current contact details")).toBe(composed);
    expect(composed?.accounts).toEqual({ [ACC1]: "FAIL", [ACC2]: "PASS" });
    expect(composed?.checkIds).toEqual([
      "account_maintain_current_contact_details",
    ]);
    expect(composed?.scanIdsByAccount[ACC1]).toEqual(["scan-1"]);

    // Nameless requirements register just the id.
    expect(extras.get("1.2")).toBeDefined();
  });
});

describe("computeAccountBreakdown", () => {
  it("scores each account over its contributed non-manual requirements", () => {
    const breakdown = computeAccountBreakdown(buildAttrs());

    expect(breakdown).toHaveLength(2);
    // Server account order (sorted by alias) is preserved.
    expect(breakdown[0].id).toBe(ACC1);
    expect(breakdown[0].label).toBe("prod (123456789012)");
    expect(breakdown[0].pass).toBe(1);
    expect(breakdown[0].fail).toBe(1);
    expect(breakdown[0].score).toBe(50);

    // Account 2 contributed only one PASS row; the requirement it skipped
    // must not drag its score.
    expect(breakdown[1].label).toBe("210987654321");
    expect(breakdown[1].pass).toBe(1);
    expect(breakdown[1].fail).toBe(0);
    expect(breakdown[1].score).toBe(100);
  });
});

describe("accountDisplayLabel", () => {
  it("prefers alias with uid in parentheses, falls back to uid", () => {
    expect(accountDisplayLabel({ id: ACC1, uid: "123", alias: "prod" })).toBe(
      "prod (123)",
    );
    expect(accountDisplayLabel({ id: ACC2, uid: "456", alias: null })).toBe(
      "456",
    );
  });
});
