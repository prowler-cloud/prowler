import {
  adaptAttackSurfaceOverview,
  getAttackSurfaceOverview,
} from "@/actions/overview";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../lib/filter-params";
import { AttackSurface } from "./attack-surface";

export const AttackSurfaceSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const response = await getAttackSurfaceOverview({ filters });

  const items = adaptAttackSurfaceOverview(response);

  return <AttackSurface items={items} filters={filters} />;
};
