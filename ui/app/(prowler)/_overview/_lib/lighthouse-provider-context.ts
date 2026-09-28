import {
  buildFilteredProviderContext,
  buildProviderGroupContext,
} from "@/lib/lighthouse/context/contributions";
import type { SearchParamsProps } from "@/types";
import type { ProviderGroup } from "@/types/components";
import type { LighthouseProviderContextItem } from "@/types/lighthouse-context";
import type { ProviderProps } from "@/types/providers";

import { parseFilterIds } from "./provider-scope";

const OVERVIEW_PATHNAME = "/";
// Bounded so provider items take a small share of the context item budget;
// under byte pressure the compiler additionally evicts provider items first.
const MAX_PROVIDER_ITEMS = 2;
const MAX_TOTAL_ITEMS = 3;

interface OverviewProviderContextInput {
  searchParams: SearchParamsProps;
  providers: ProviderProps[];
  groups: ProviderGroup[];
}

export function buildOverviewProviderContextItems({
  searchParams,
  providers,
  groups,
}: OverviewProviderContextInput): LighthouseProviderContextItem[] {
  // Dedupe before slicing so a repeated id cannot fill the bounded slots and
  // silently push the remaining selected providers out of the context.
  const providerIds = Array.from(
    new Set(parseFilterIds(searchParams["filter[provider_id__in]"])),
  );
  const groupIds = Array.from(
    new Set(parseFilterIds(searchParams["filter[provider_groups__in]"])),
  );

  const providerItems = providerIds
    .map((id) => providers.find((provider) => provider.id === id))
    .filter((provider) => provider !== undefined)
    .slice(0, MAX_PROVIDER_ITEMS)
    .map((provider) =>
      buildFilteredProviderContext({
        pathname: OVERVIEW_PATHNAME,
        id: provider.id,
        uid: provider.attributes.uid,
        type: provider.attributes.provider,
        alias: provider.attributes.alias ?? undefined,
      }),
    );

  const groupItems = groupIds
    .map((id) => groups.find((group) => group.id === id))
    .filter((group) => group !== undefined)
    .map((group) =>
      buildProviderGroupContext({
        pathname: OVERVIEW_PATHNAME,
        id: group.id,
        name: group.attributes.name,
      }),
    );

  return [...providerItems, ...groupItems].slice(0, MAX_TOTAL_ITEMS);
}
