import { describe, expect, it } from "vitest";

import { ProviderGroup } from "@/types/components";
import { ProviderProps } from "@/types/providers";
import { ScanEntity } from "@/types/scans";

import {
  buildFindingGroupFilterOption,
  buildFindingsFilterChips,
  getFindingsFilterDisplayValue,
} from "./findings-filters.utils";

const providerGroups: ProviderGroup[] = [
  {
    type: "provider-groups",
    id: "group-1",
    attributes: { name: "Production", inserted_at: "", updated_at: "" },
    relationships: {
      providers: { meta: { count: 0 }, data: [] },
      roles: { meta: { count: 0 }, data: [] },
    },
    links: { self: "" },
  },
];

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
      providerInfo: {
        provider: "aws",
        alias: "Scan Account",
        uid: "123456789012",
      },
      attributes: {
        name: "Nightly scan",
        completed_at: "2026-04-07T10:00:00Z",
      },
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

  it("shows the provider group name for provider_groups filters instead of the raw group id", () => {
    expect(
      getFindingsFilterDisplayValue("filter[provider_groups__in]", "group-1", {
        providerGroups,
      }),
    ).toBe("Production");
  });

  it("keeps the raw value when the provider group cannot be resolved", () => {
    expect(
      getFindingsFilterDisplayValue(
        "filter[provider_groups__in]",
        "missing-group",
        { providerGroups },
      ),
    ).toBe("missing-group");
  });

  it("shows the resolved scan badge label for scan filters instead of formatting the raw scan id", () => {
    expect(
      getFindingsFilterDisplayValue("filter[scan__in]", "scan-1", { scans }),
    ).toBe("AWS - Nightly scan");
  });

  it("normalizes finding statuses for display", () => {
    expect(getFindingsFilterDisplayValue("filter[status__in]", "FAIL")).toBe(
      "Fail",
    );
  });

  it("normalizes severities for display", () => {
    expect(
      getFindingsFilterDisplayValue("filter[severity__in]", "critical"),
    ).toBe("Critical");
  });

  it("formats delta values for display", () => {
    expect(getFindingsFilterDisplayValue("filter[delta__in]", "new")).toBe(
      "New",
    );
  });

  it("formats the singular delta filter the same as delta__in", () => {
    // The API registers the filter as `filter[delta]` (exact), not `delta__in`.
    // Both shapes must resolve to the same human label so chips don't show
    // the raw "new" going through formatLabel ("NEW" via the 3-letter acronym heuristic).
    expect(getFindingsFilterDisplayValue("filter[delta]", "new")).toBe("New");
    expect(getFindingsFilterDisplayValue("filter[delta]", "changed")).toBe(
      "Changed",
    );
  });

  it("uses the finding group title for check_id filters when available", () => {
    expect(
      getFindingsFilterDisplayValue(
        "filter[check_id]",
        "teams_external_users_can_join",
        {
          checkTitles: {
            teams_external_users_can_join:
              "External Teams users can join meetings",
          },
        },
      ),
    ).toBe("External Teams users can join meetings");
  });

  it("keeps the check id when no finding group title is available", () => {
    expect(
      getFindingsFilterDisplayValue(
        "filter[check_id]",
        "teams_external_users_can_join",
      ),
    ).toBe("teams_external_users_can_join");
  });

  it("uses the provider display name regardless of account alias/uid", () => {
    expect(
      getFindingsFilterDisplayValue("filter[scan__in]", "scan-2", {
        scans: [
          ...scans,
          makeScanMap("scan-2", {
            providerInfo: { provider: "aws", uid: "210987654321" },
            attributes: {
              name: "Weekly scan",
              completed_at: "2026-04-08T10:00:00Z",
            },
          }),
        ],
      }),
    ).toBe("AWS - Weekly scan");
  });

  it("returns only the provider name when the scan name is missing", () => {
    expect(
      getFindingsFilterDisplayValue("filter[scan__in]", "scan-3", {
        scans: [
          ...scans,
          makeScanMap("scan-3", {
            providerInfo: {
              provider: "gcp",
              alias: "Fallback Account",
              uid: "333333333333",
            },
            attributes: {
              name: "",
              completed_at: "2026-04-08T10:00:00Z",
            },
          }),
        ],
      }),
    ).toBe("Google Cloud");
  });

  it("keeps the raw scan value when the scan cannot be resolved", () => {
    expect(
      getFindingsFilterDisplayValue("filter[scan__in]", "missing-scan", {
        scans,
      }),
    ).toBe("missing-scan");
  });

  it("passes through date values for inserted_at__gte filters", () => {
    expect(
      getFindingsFilterDisplayValue(
        "filter[inserted_at__gte]",
        "2026-04-03",
        {},
      ),
    ).toBe("2026-04-03");
  });

  it("passes through date values for inserted_at__lte filters", () => {
    expect(
      getFindingsFilterDisplayValue(
        "filter[inserted_at__lte]",
        "2026-04-07",
        {},
      ),
    ).toBe("2026-04-07");
  });
});

describe("buildFindingsFilterChips", () => {
  it("creates one chip per filter with normalized labels", () => {
    // Given — this is the exact pending state derived from the LinkToFindings URL:
    // /findings?sort=...&filter[status__in]=FAIL&filter[delta]=new
    const pendingFilters = {
      "filter[status__in]": ["FAIL"],
      "filter[delta]": ["new"],
    };

    // When
    const chips = buildFindingsFilterChips(pendingFilters);

    // Then — both filters must appear; the delta chip must use "Delta" as label
    // (not the raw "filter[delta]") and "New" as displayValue (not "NEW" via
    // the short-word acronym heuristic in formatLabel).
    expect(chips).toEqual([
      {
        key: "filter[status__in]",
        label: "Status",
        value: "FAIL",
        displayValue: "Fail",
      },
      {
        key: "filter[delta]",
        label: "Delta",
        value: "new",
        displayValue: "New",
      },
    ]);
  });

  it("labels provider group chips and resolves their names", () => {
    const chips = buildFindingsFilterChips(
      { "filter[provider_groups__in]": ["group-1"] },
      { providerGroups },
    );

    expect(chips).toEqual([
      {
        key: "filter[provider_groups__in]",
        label: "Provider Group",
        value: "group-1",
        displayValue: "Production",
      },
    ]);
  });

  it("treats filter[delta] and filter[delta__in] identically", () => {
    // Given
    const chipsSingular = buildFindingsFilterChips({
      "filter[delta]": ["new", "changed"],
    });
    const chipsPlural = buildFindingsFilterChips({
      "filter[delta__in]": ["new", "changed"],
    });

    // Then — both shapes produce the same human labels and grouped display values
    expect(
      chipsSingular.map((c) => ({ label: c.label, v: c.displayValue })),
    ).toEqual([{ label: "Delta", v: "+2" }]);
    expect(chipsSingular[0].displayValues).toEqual(["New", "Changed"]);
    expect(
      chipsPlural.map((c) => ({ label: c.label, v: c.displayValue })),
    ).toEqual([{ label: "Delta", v: "+2" }]);
    expect(chipsPlural[0].displayValues).toEqual(["New", "Changed"]);
  });

  it("renders filter[check_id] as a first-class Finding Group chip", () => {
    // Given - exact deep-link params from the grouped findings page.
    const chips = buildFindingsFilterChips(
      {
        "filter[check_id]": ["teams_external_users_can_join"],
      },
      {
        checkTitles: {
          teams_external_users_can_join:
            "External Teams users can join meetings",
        },
      },
    );

    expect(chips).toEqual([
      {
        key: "filter[check_id]",
        label: "Finding Group",
        value: "teams_external_users_can_join",
        displayValue: "External Teams users can join meetings",
      },
    ]);
  });

  it("renders filter[check_id__in] with the Finding Group chip label", () => {
    const chips = buildFindingsFilterChips({
      "filter[check_id__in]": ["teams_external_users_can_join"],
    });

    expect(chips).toEqual([
      {
        key: "filter[check_id__in]",
        label: "Finding Group",
        value: "teams_external_users_can_join",
        displayValue: "teams_external_users_can_join",
      },
    ]);
  });

  it("skips muted filters because the table toolbar owns that control", () => {
    const chips = buildFindingsFilterChips({
      "filter[muted]": ["include"],
      "filter[delta]": ["new"],
    });

    // Only the delta chip — muted state is shown by the table checkbox.
    expect(chips).toHaveLength(1);
    expect(chips[0].key).toBe("filter[delta]");
  });

  it("surfaces unmapped keys using the raw key as label (fallback)", () => {
    const chips = buildFindingsFilterChips({
      "filter[unknown_future_key]": ["value"],
    });

    expect(chips).toEqual([
      {
        key: "filter[unknown_future_key]",
        label: "filter[unknown_future_key]",
        value: "value",
        displayValue: "Value",
      },
    ]);
  });
});

describe("buildFindingGroupFilterOption", () => {
  it("builds a selectable Finding Group filter from fetched options and URL-backed values", () => {
    // Given
    const filter = buildFindingGroupFilterOption({
      checkOptions: [
        {
          checkId: "teams_external_users_can_join",
          checkTitle: "External Teams users can join meetings",
        },
      ],
      selectedCheckIds: ["s3_bucket_public_access"],
      selectedCheckIdsIn: ["teams_external_users_can_join"],
      checkTitles: {
        teams_external_users_can_join: "External Teams users can join meetings",
      },
    });

    // Then
    expect(filter).toMatchObject({
      key: "check_id",
      labelCheckboxGroup: "Finding Group",
      values: ["teams_external_users_can_join", "s3_bucket_public_access"],
      index: 3,
    });
    expect(filter?.labelFormatter?.("teams_external_users_can_join")).toBe(
      "External Teams users can join meetings",
    );
    expect(filter?.labelFormatter?.("s3_bucket_public_access")).toBe(
      "s3_bucket_public_access",
    );
  });

  it("omits the Finding Group filter when there are no selectable or URL-backed values", () => {
    expect(
      buildFindingGroupFilterOption({
        checkOptions: [],
        selectedCheckIds: [],
        selectedCheckIdsIn: [],
        checkTitles: {},
      }),
    ).toBeNull();
  });
});
