import { getFindingsByStatus } from "@/actions/overview/overview";
import { getProviders } from "@/actions/providers";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../lib/filter-params";
import { StatusChart } from "../status-chart/status-chart";

export const CheckFindingsSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const [findingsByStatus, providersData] = await Promise.all([
    getFindingsByStatus({ filters }),
    getProviders({ page: 1, pageSize: 200 }),
  ]);

  if (!findingsByStatus) {
    return (
      <div className="flex h-[400px] w-full max-w-md items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
        <p className="text-zinc-400">Failed to load findings data</p>
      </div>
    );
  }

  const attributes = findingsByStatus?.data?.attributes || {};

  const {
    total = 0,
    fail = 0,
    pass = 0,
    fail_new = 0,
    pass_new = 0,
  } = attributes;

  return (
    <StatusChart
      totalFindings={total}
      failFindingsData={{
        total: fail,
        new: fail_new,
      }}
      passFindingsData={{
        total: pass,
        new: pass_new,
      }}
      providers={providersData?.data}
    />
  );
};
