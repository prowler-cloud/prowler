import { describe, expect, it } from "vitest";

import type { ProviderGroup } from "@/types/components";
import type { ScanEntity } from "@/types/scans";

import {
  getProviderGroupDisplayValue,
  getScanEntityLabel,
  hasDateFilter,
  hasDateOrScanFilter,
  hasHistoricalFindingFilter,
} from "./helper-filters";

const makeProviderGroup = (id: string, name: string): ProviderGroup =>
  ({
    type: "provider-groups",
    id,
    attributes: { name, inserted_at: "", updated_at: "" },
  }) as ProviderGroup;

function makeScan(overrides: Partial<ScanEntity> = {}): ScanEntity {
  return {
    id: "scan-1",
    providerInfo: {
      provider: "aws",
      alias: "Production",
      uid: "123456789012",
    },
    attributes: {
      name: "Nightly scan",
      completed_at: "2026-04-07T10:00:00Z",
    },
    ...overrides,
  };
}

describe("getProviderGroupDisplayValue", () => {
  const groups = [
    makeProviderGroup("g1", "Production"),
    makeProviderGroup("g2", "Staging"),
  ];

  it("resolves the group name when the id matches", () => {
    expect(getProviderGroupDisplayValue("g1", groups)).toBe("Production");
  });

  it("falls back to the raw id when the group is not found", () => {
    expect(getProviderGroupDisplayValue("unknown", groups)).toBe("unknown");
  });

  it("falls back to the raw id when the group name is empty", () => {
    expect(
      getProviderGroupDisplayValue("g3", [makeProviderGroup("g3", "")]),
    ).toBe("g3");
  });
});

describe("hasDateOrScanFilter", () => {
  it("returns true for scan filters", () => {
    expect(hasDateOrScanFilter({ "filter[scan__in]": "scan-1" })).toBe(true);
  });

  it("returns true for exact scan filters", () => {
    expect(hasDateOrScanFilter({ "filter[scan]": "scan-1" })).toBe(true);
  });

  it("returns true for inserted_at filters", () => {
    expect(
      hasDateOrScanFilter({ "filter[inserted_at__gte]": "2026-04-01" }),
    ).toBe(true);
  });
});

describe("hasDateFilter", () => {
  it("returns true for inserted_at filters", () => {
    expect(hasDateFilter({ "filter[inserted_at__lte]": "2026-04-07" })).toBe(
      true,
    );
  });

  it("returns false for scan filters only", () => {
    expect(hasDateFilter({ "filter[scan__in]": "scan-1" })).toBe(false);
  });
});

describe("getScanEntityLabel", () => {
  it("combines provider display name and scan name with a dash", () => {
    expect(getScanEntityLabel(makeScan())).toBe("AWS - Nightly scan");
  });

  it("uses the provider type even when the account alias is present", () => {
    // Guard against regressions where alias/uid leak back into the label.
    expect(
      getScanEntityLabel(
        makeScan({
          providerInfo: {
            provider: "azure",
            alias: "Production",
            uid: "subscription-xyz",
          },
        }),
      ),
    ).toBe("Azure - Nightly scan");
  });

  it("renders the provider display name for non-AWS providers", () => {
    expect(
      getScanEntityLabel(makeScan({ providerInfo: { provider: "gcp" } })),
    ).toBe("Google Cloud - Nightly scan");
  });

  it("returns only the provider name when the scan name is missing", () => {
    expect(
      getScanEntityLabel(
        makeScan({
          attributes: { name: "", completed_at: "2026-04-07T10:00:00Z" },
        }),
      ),
    ).toBe("AWS");
  });
});

describe("hasHistoricalFindingFilter", () => {
  it("returns true for inserted_at filters", () => {
    expect(
      hasHistoricalFindingFilter({ "filter[inserted_at__gte]": "2026-04-01" }),
    ).toBe(true);
  });

  it("returns true for scan filters", () => {
    expect(hasHistoricalFindingFilter({ "filter[scan__in]": "scan-1" })).toBe(
      true,
    );
  });

  it("returns true for exact scan filters", () => {
    expect(hasHistoricalFindingFilter({ "filter[scan]": "scan-1" })).toBe(true);
  });

  it("returns false when neither date nor scan filters are active", () => {
    expect(
      hasHistoricalFindingFilter({ "filter[provider_type__in]": "aws" }),
    ).toBe(false);
  });
});
