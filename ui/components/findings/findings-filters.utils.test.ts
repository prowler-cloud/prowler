import { describe, expect, it } from "vitest";

import { ProviderProps } from "@/types/providers";
import { ScanEntity } from "@/types/scans";

import { getFindingsFilterDisplayValue } from "./findings-filters.utils";

function makeProvider(
  overrides: Partial<ProviderProps> & { id: string },
): ProviderProps {
  return {
    type: "providers",
    attributes: {
      provider: "aws",
      uid: "123456789012",
      alias: "Production Account",
      status: "completed",
      resources: 10,
      connection: { connected: true, last_checked_at: "2026-04-07T10:00:00Z" },
      scanner_args: {
        only_logs: false,
        excluded_checks: [],
        aws_retries_max_attempts: 3,
      },
      inserted_at: "2026-04-07T10:00:00Z",
      updated_at: "2026-04-07T10:00:00Z",
      created_by: { object: "user", id: "user-1" },
    },
    relationships: {
      secret: { data: null },
      provider_groups: { meta: { count: 0 }, data: [] },
    },
    ...overrides,
  } as ProviderProps;
}

function makeScanMap(
  scanId: string,
  overrides?: Partial<ScanEntity>,
): { [scanId: string]: ScanEntity } {
  return {
    [scanId]: {
      id: scanId,
      providerInfo: { provider: "aws", alias: "Scan Account", uid: "123456789012" },
      attributes: { name: "Nightly scan", completed_at: "2026-04-07T10:00:00Z" },
      ...overrides,
    },
  };
}

const providers = [makeProvider({ id: "provider-1" })];
const scans = [makeScanMap("scan-1")];

describe("getFindingsFilterDisplayValue", () => {
  it("shows the account alias for provider_id filters instead of the raw provider id", () => {
    expect(
      getFindingsFilterDisplayValue("filter[provider_id__in]", "provider-1", {
        providers,
      }),
    ).toBe("Production Account");
  });

  it("falls back to the provider uid when the alias is empty", () => {
    expect(
      getFindingsFilterDisplayValue("filter[provider_id__in]", "provider-2", {
        providers: [
          ...providers,
          makeProvider({
            id: "provider-2",
            attributes: {
              ...providers[0].attributes,
              alias: "",
              uid: "210987654321",
            },
          }),
        ],
      }),
    ).toBe("210987654321");
  });

  it("keeps the raw value when the provider cannot be resolved", () => {
    expect(
      getFindingsFilterDisplayValue(
        "filter[provider_id__in]",
        "missing-provider",
        { providers },
      ),
    ).toBe("missing-provider");
  });

  it("shows the resolved scan badge label for scan filters instead of formatting the raw scan id", () => {
    expect(
      getFindingsFilterDisplayValue("filter[scan__in]", "scan-1", { scans }),
    ).toBe("Scan Account");
  });

  it("falls back to the scan provider uid when the alias is missing", () => {
    expect(
      getFindingsFilterDisplayValue("filter[scan__in]", "scan-2", {
        scans: [
          ...scans,
          makeScanMap("scan-2", {
            providerInfo: { provider: "aws", uid: "210987654321" },
            attributes: { name: "Weekly scan", completed_at: "2026-04-08T10:00:00Z" },
          }),
        ],
      }),
    ).toBe("210987654321");
  });

  it("keeps the raw scan value when the scan cannot be resolved", () => {
    expect(
      getFindingsFilterDisplayValue("filter[scan__in]", "missing-scan", {
        scans,
      }),
    ).toBe("missing-scan");
  });
});
