import {
  BaseCard,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn";
import { getFindingsByStatus } from "@/actions/overview/overview";
import { SearchParamsProps } from "@/types";
import { StatusChart } from "./status-chart";

const FILTER_PREFIX = "filter[";

function pickFilterParams(
  params: SearchParamsProps | undefined | null,
): Record<string, string | string[] | undefined> {
  if (!params) return {};
  return Object.fromEntries(
    Object.entries(params).filter(([key]) => key.startsWith(FILTER_PREFIX)),
  );
}

export const StatusChartSSR = async ({
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
    <BaseCard>
      <CardHeader>
        <CardTitle>Check Findings</CardTitle>
      </CardHeader>

      <CardContent>
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
      </CardContent>
    </BaseCard>
  );
};