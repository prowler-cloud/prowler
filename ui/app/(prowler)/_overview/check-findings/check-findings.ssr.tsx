import { getFindingsByStatus } from "@/actions/overview";
import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import { buildFindingStatusSummaryContext } from "@/lib/lighthouse/context/contributions";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";
import { StatusChart } from "../status-chart/_components/status-chart";

export const CheckFindingsSSR = async ({ searchParams }: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);

  const findingsByStatus = await getFindingsByStatus({ filters });

  // handleApiResponse resolves truthy on 4xx ({error, status}) and empty
  // bodies ({success, status}), so only a payload with attributes is data.
  if (!findingsByStatus?.data?.attributes) {
    return (
      <div className="flex h-[400px] w-full max-w-md items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
        <p className="text-zinc-400">Failed to load findings data</p>
      </div>
    );
  }

  const {
    fail = 0,
    pass = 0,
    fail_new = 0,
    pass_new = 0,
  } = findingsByStatus.data.attributes;

  return (
    <>
      <LighthouseContextContributor
        contributorId="overview-status-summary"
        item={buildFindingStatusSummaryContext({
          pathname: "/",
          passed: pass,
          failed: fail,
          newPassed: pass_new,
          newFailed: fail_new,
        })}
      />
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
    </>
  );
};
