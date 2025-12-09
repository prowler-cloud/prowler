import {
  adaptResourcesInventoryOverview,
  getResourcesInventoryOverview,
} from "@/actions/overview";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";
import { ResourcesInventory } from "./_components/resources-inventory";

export const ResourcesInventorySSR = async ({
  searchParams,
}: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);

  const response = await getResourcesInventoryOverview({ filters });

  const items = adaptResourcesInventoryOverview(response);

  return <ResourcesInventory items={items} filters={filters} />;
};
