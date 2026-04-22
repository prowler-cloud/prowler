import { Info } from "lucide-react";

import { getMuteRules } from "@/actions/mute-rules";
import { Card, Skeleton } from "@/components/shadcn";
import { SearchParamsProps } from "@/types/components";

import { hydrateMuteRuleTargetPreviews } from "./mute-rule-target-previews";
import { MuteRulesTableClient } from "./mute-rules-table-client";

interface MuteRulesTableProps {
  searchParams: SearchParamsProps;
}

export async function MuteRulesTable({ searchParams }: MuteRulesTableProps) {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);
  const sort = searchParams.sort?.toString() || "-inserted_at";
  const search = searchParams["filter[search]"]?.toString();

  const muteRulesData = await getMuteRules({
    page,
    pageSize,
    sort,
    filters: search ? { search } : undefined,
  });

  const muteRules = await hydrateMuteRuleTargetPreviews(
    muteRulesData?.data || [],
  );

  const hasActiveSearch = Boolean(search);

  if (muteRules.length === 0 && !hasActiveSearch) {
    return (
      <Card variant="base" className="gap-0">
        <div className="flex flex-col items-center justify-center gap-4 text-center">
          <div className="border-border-neutral-secondary bg-bg-neutral-tertiary rounded-full border p-4">
            <Info className="text-text-neutral-tertiary size-8" />
          </div>
          <div>
            <h3 className="text-text-neutral-primary text-lg font-medium">
              No mute rules yet
            </h3>
            <p className="text-text-neutral-secondary mt-1 text-sm">
              Mute rules are created when you mute findings from the Findings
              page. Select findings and click &quot;Mute&quot; to create your
              first rule.
            </p>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <MuteRulesTableClient
      muteRules={muteRules}
      metadata={
        muteRulesData?.meta ? { ...muteRulesData.meta, version: "" } : undefined
      }
    />
  );
}

function MuteRulesSkeletonRow() {
  return (
    <tr className="border-border-neutral-secondary border-b last:border-b-0">
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-32 rounded" />
      </td>
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-56 rounded" />
      </td>
      <td className="px-3 py-4">
        <div className="border-border-neutral-secondary flex w-[240px] items-center gap-2 rounded-md border px-3 py-2">
          <Skeleton className="h-4 flex-1 rounded" />
          <Skeleton className="size-4 rounded" />
        </div>
      </td>
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-28 rounded" />
      </td>
      <td className="px-3 py-4">
        <Skeleton className="h-6 w-12 rounded-full" />
      </td>
      <td className="px-2 py-4">
        <Skeleton className="size-8 rounded-md" />
      </td>
    </tr>
  );
}

export function MuteRulesTableSkeleton() {
  return (
    <div
      data-testid="mute-rules-table-skeleton"
      className="rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary flex w-full flex-col gap-4 overflow-hidden border p-4"
    >
      <div
        data-testid="mute-rules-table-skeleton-intro"
        className="flex flex-col gap-1.5"
      >
        <Skeleton className="h-5 w-40 rounded" />
        <Skeleton className="h-3 w-[28rem] max-w-full rounded" />
      </div>

      <div className="flex items-center justify-between">
        <Skeleton className="h-9 w-64 rounded-md" />
        <Skeleton className="h-4 w-24 rounded" />
      </div>

      <table className="w-full" aria-hidden="true">
        <thead>
          <tr className="border-border-neutral-secondary border-b">
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-12 rounded" />
            </th>
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-14 rounded" />
            </th>
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-16 rounded" />
            </th>
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-16 rounded" />
            </th>
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-16 rounded" />
            </th>
            <th className="w-10 py-3" />
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: 8 }).map((_, index) => (
            <MuteRulesSkeletonRow key={index} />
          ))}
        </tbody>
      </table>

      <div className="flex items-center justify-between pt-2">
        <div className="flex items-center gap-2">
          <Skeleton className="h-4 w-24 rounded" />
          <Skeleton className="h-9 w-16 rounded-md" />
        </div>
        <div className="flex items-center gap-4">
          <Skeleton className="h-4 w-24 rounded" />
          <div className="flex gap-1">
            <Skeleton className="size-9 rounded-md" />
            <Skeleton className="size-9 rounded-md" />
            <Skeleton className="size-9 rounded-md" />
            <Skeleton className="size-9 rounded-md" />
          </div>
        </div>
      </div>
    </div>
  );
}
