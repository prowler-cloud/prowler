import { describe, expect, it } from "vitest";

import type { ProviderGroup } from "@/types/components";
import type { ProviderProps } from "@/types/providers";

import {
  buildResourcesFilterChips,
  getResourcesFilterDisplayValue,
} from "./resources-filters.utils";

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

const providers: ProviderProps[] = [];

describe("getResourcesFilterDisplayValue", () => {
  it("shows the provider group name for provider_groups filters", () => {
    expect(
      getResourcesFilterDisplayValue(
        "filter[provider_groups__in]",
        "group-1",
        providers,
        providerGroups,
      ),
    ).toBe("Production");
  });

  it("keeps the raw value when the provider group cannot be resolved", () => {
    expect(
      getResourcesFilterDisplayValue(
        "filter[provider_groups__in]",
        "missing-group",
        providers,
        providerGroups,
      ),
    ).toBe("missing-group");
  });
});

describe("buildResourcesFilterChips", () => {
  it("labels provider group chips and resolves their names", () => {
    const chips = buildResourcesFilterChips(
      { "filter[provider_groups__in]": ["group-1"] },
      providers,
      providerGroups,
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
});
