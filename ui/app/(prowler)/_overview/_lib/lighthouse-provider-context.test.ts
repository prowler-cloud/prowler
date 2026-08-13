import { describe, expect, it } from "vitest";

import type { ProviderGroup } from "@/types/components";
import { ProviderProps } from "@/types/providers";

import { buildOverviewProviderContextItems } from "./lighthouse-provider-context";

const makeProvider = (
  id: string,
  provider: string,
  uid: string,
  alias: string | null,
): ProviderProps =>
  ({
    id,
    attributes: { provider, uid, alias },
  }) as unknown as ProviderProps;

const makeGroup = (id: string, name: string): ProviderGroup =>
  ({ id, attributes: { name } }) as unknown as ProviderGroup;

const providers = [
  makeProvider("prov-1", "aws", "111111111111", "Production"),
  makeProvider("prov-2", "gcp", "gcp-project", null),
  makeProvider("prov-3", "azure", "sub-3", "Backup"),
];
const groups = [makeGroup("group-1", "Production accounts")];

describe("buildOverviewProviderContextItems", () => {
  it("resolves URL-filtered provider ids to labeled context items", () => {
    const items = buildOverviewProviderContextItems({
      searchParams: { "filter[provider_id__in]": "prov-1,prov-2,unknown" },
      providers,
      groups,
    });

    expect(items).toEqual([
      expect.objectContaining({
        kind: "provider",
        id: "prov-1",
        source: "automatic",
        scopeKey: "overview:/",
        label: "Provider: Production",
        providerUid: "111111111111",
        providerType: "aws",
      }),
      expect.objectContaining({
        id: "prov-2",
        label: "Provider: gcp-project",
        providerType: "gcp",
      }),
    ]);
  });

  it("dedupes repeated provider ids before filling the bounded slots", () => {
    const items = buildOverviewProviderContextItems({
      searchParams: {
        "filter[provider_id__in]": "prov-1,prov-1,prov-1,prov-2,prov-3",
      },
      providers,
      groups,
    });

    expect(items.map((item) => item.id)).toEqual(["prov-1", "prov-2"]);
  });

  it("resolves URL-filtered group ids to labeled group items", () => {
    const items = buildOverviewProviderContextItems({
      searchParams: { "filter[provider_groups__in]": "group-1,unknown" },
      providers,
      groups,
    });

    expect(items).toEqual([
      expect.objectContaining({
        kind: "provider",
        id: "group-group-1",
        label: "Provider group: Production accounts",
      }),
    ]);
  });

  it("caps combined items to keep the context budget", () => {
    const items = buildOverviewProviderContextItems({
      searchParams: {
        "filter[provider_id__in]": "prov-1,prov-2,prov-3",
        "filter[provider_groups__in]": "group-1",
      },
      providers,
      groups,
    });

    expect(items).toHaveLength(3);
    expect(items.map((item) => item.id)).toEqual([
      "prov-1",
      "prov-2",
      "group-group-1",
    ]);
  });

  it("returns no items when the URL has no provider filters", () => {
    expect(
      buildOverviewProviderContextItems({
        searchParams: {},
        providers,
        groups,
      }),
    ).toEqual([]);
  });
});
