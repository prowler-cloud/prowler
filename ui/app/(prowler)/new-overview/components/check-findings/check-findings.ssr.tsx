import { getFindingsByStatus } from "@/actions/overview/overview";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../lib/filter-params";
import { StatusChart } from "../status-chart/status-chart";

export const CheckFindingsSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const findingsByStatus = await getFindingsByStatus({ filters });

  if (!findingsByStatus) {
    return (
      <div className="flex h-[400px] w-full max-w-md items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
        <p className="text-zinc-400">Failed to load findings data</p>
      </div>
    );
  }

  const {
    fail = 0,
    pass = 0,
    muted_new = 0,
    muted_changed = 0,
    fail_new = 0,
    pass_new = 0,
  } = findingsByStatus?.data?.attributes || {};

  const mutedTotal = muted_new + muted_changed;

  return (
    <StatusChart
      failFindingsData={{
        total: fail,
        new: fail_new,
        muted: mutedTotal,
      }}
      passFindingsData={{
        total: pass,
        new: pass_new,
        muted: mutedTotal,
      }}
    />
  );
};
