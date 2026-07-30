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
