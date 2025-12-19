import { getFindingsByStatus } from "@/actions/overview";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";
import { StatusChart } from "../status-chart/_components/status-chart";

export const CheckFindingsSSR = async ({ searchParams }: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);

  const findingsByStatus = await getFindingsByStatus({ filters });

  if (!findingsByStatus) {
    return (
      <div className="flex h-[400px] w-full max-w-md items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
        <p className="text-zinc-400">Failed to load findings data</p>
      </div>
    );
  }

  const attributes = findingsByStatus?.data?.attributes || {};

  const { fail = 0, pass = 0, fail_new = 0, pass_new = 0 } = attributes;

  return (
    <StatusChart
      failFindingsData={{
        total: fail,
        new: fail_new,
      }}
      passFindingsData={{
        total: pass,
        new: pass_new,
      }}
    />
  );
};
