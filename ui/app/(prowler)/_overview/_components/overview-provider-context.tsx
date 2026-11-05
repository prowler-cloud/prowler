import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import type { SearchParamsProps } from "@/types";
import type { ProviderGroup } from "@/types/components";
import type { ProviderProps } from "@/types/providers";

import { buildOverviewProviderContextItems } from "../_lib/lighthouse-provider-context";

interface OverviewProviderContextProps {
  searchParams: SearchParamsProps;
  providers: ProviderProps[];
  groups: ProviderGroup[];
}

export const OverviewProviderContext = ({
  searchParams,
  providers,
  groups,
}: OverviewProviderContextProps) => {
  const items = buildOverviewProviderContextItems({
    searchParams,
    providers,
    groups,
  });

  return (
    <>
      {items.map((item) => (
        <LighthouseContextContributor
          key={item.id}
          contributorId={`overview-provider-${item.id}`}
          item={item}
        />
      ))}
    </>
  );
};
