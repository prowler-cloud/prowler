import {
  adaptAttackSurfaceOverview,
  getAttackSurfaceOverview,
} from "@/actions/overview";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";
import { AttackSurface } from "./_components/attack-surface";

export const AttackSurfaceSSR = async ({ searchParams }: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);

  const response = await getAttackSurfaceOverview({ filters });

  const items = adaptAttackSurfaceOverview(response);

  return <AttackSurface items={items} filters={filters} />;
};
