import { describe, expect, it, vi } from "vitest";

vi.mock("../../_actions/cross-account", () => ({
  getCrossAccountPdfBinary: vi.fn(),
}));

vi.mock("@/components/shadcn/toast", () => ({
  toast: vi.fn(),
  ToastAction: () => null,
}));

vi.mock("@/lib/helper", () => ({
  downloadFile: vi.fn(),
}));

import { buildCrossAccountPdfTaskScope } from "../cross-account-pdf";

describe("buildCrossAccountPdfTaskScope", () => {
  it("normalizes set-like filter ordering into one task scope", () => {
    const first = buildCrossAccountPdfTaskScope("cis_2.0_aws", "aws", {
      scanIds: ["scan-2", "scan-1"],
      providerIds: "provider-2,provider-1",
    });
    const second = buildCrossAccountPdfTaskScope("cis_2.0_aws", "aws", {
      scanIds: ["scan-1", "scan-2"],
      providerIds: "provider-1,provider-2",
    });

    expect(first).toBe(second);
  });

  it("keeps reports from different provider types in separate scopes", () => {
    const awsScope = buildCrossAccountPdfTaskScope("cis_2.0_aws", "aws", {
      scanIds: ["scan-1"],
    });
    const gcpScope = buildCrossAccountPdfTaskScope("cis_2.0_aws", "gcp", {
      scanIds: ["scan-1"],
    });

    expect(awsScope).not.toBe(gcpScope);
  });
});
