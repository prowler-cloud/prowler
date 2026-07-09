import { describe, expect, it, vi } from "vitest";

vi.mock("../../_actions/cross-provider", () => ({
  getCrossProviderPdfBinary: vi.fn(),
}));

vi.mock("@/components/shadcn/toast", () => ({
  toast: vi.fn(),
  ToastAction: () => null,
}));

vi.mock("@/lib/helper", () => ({
  downloadFile: vi.fn(),
}));

import { buildCrossProviderPdfTaskScope } from "../cross-provider-pdf";

describe("buildCrossProviderPdfTaskScope", () => {
  it("normalizes set-like filter ordering into one task scope", () => {
    // Given / When
    const first = buildCrossProviderPdfTaskScope("csa_ccm_4.0", {
      scanIds: ["scan-2", "scan-1"],
      providerTypes: "gcp,aws",
      providerIds: "provider-2,provider-1",
    });
    const second = buildCrossProviderPdfTaskScope("csa_ccm_4.0", {
      scanIds: ["scan-1", "scan-2"],
      providerTypes: "aws,gcp",
      providerIds: "provider-1,provider-2",
    });

    // Then
    expect(first).toBe(second);
  });

  it("keeps reports from different effective filters in separate scopes", () => {
    // Given / When
    const euScope = buildCrossProviderPdfTaskScope("csa_ccm_4.0", {
      scanIds: ["scan-1"],
      regions: "eu-west-1",
    });
    const usScope = buildCrossProviderPdfTaskScope("csa_ccm_4.0", {
      scanIds: ["scan-1"],
      regions: "us-east-1",
    });

    // Then
    expect(euScope).not.toBe(usScope);
  });
});
