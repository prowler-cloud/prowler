import { Info } from "lucide-react";

import { getMuteRules } from "@/actions/mute-rules";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Skeleton,
} from "@/components/shadcn";
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
    <Card variant="base" className="gap-0">
      <CardHeader className="border-border-neutral-secondary mb-0 gap-3 border-b px-0 pb-5">
        <CardTitle className="text-text-neutral-primary mt-0 font-semibold">
          Simple Mutelist Rules
        </CardTitle>
        <CardDescription className="text-text-neutral-secondary">
          Rules created from the Findings page apply immediately to the matching
          findings and can be toggled on or off at any time.
        </CardDescription>
        <div className="text-text-neutral-secondary grid gap-2 text-sm">
          <p>Create rules by selecting findings and choosing mute.</p>
          <p>
            Review affected findings from the table without leaving Mutelist.
          </p>
        </div>
      </CardHeader>
      <CardContent className="px-0 pt-5">
        <MuteRulesTableClient
          muteRules={muteRules}
          metadata={
            muteRulesData?.meta
              ? { ...muteRulesData.meta, version: "" }
              : undefined
          }
        />
      </CardContent>
    </Card>
  );
}

function MuteRulesSkeletonRow() {
  return (
    <tr className="border-border-neutral-secondary border-b last:border-b-0">
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-28 rounded" />
      </td>
      <td className="px-3 py-4">
        <div className="flex flex-col gap-1.5">
          <Skeleton className="h-4 w-40 rounded" />
          <Skeleton className="h-3 w-32 rounded" />
        </div>
      </td>
      <td className="px-3 py-4">
        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex w-64 items-center gap-3 rounded-md border px-3 py-2">
          <Skeleton className="bg-bg-neutral-secondary size-8 rounded-full" />
          <div className="min-w-0 flex-1 space-y-1.5">
            <Skeleton className="h-4 w-44 rounded" />
            <Skeleton className="h-3 w-28 rounded" />
          </div>
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
        className="border-border-neutral-secondary space-y-3 border-b pb-5"
      >
        <Skeleton className="h-6 w-44 rounded" />
        <Skeleton className="h-4 w-[36rem] max-w-full rounded" />
        <Skeleton className="h-4 w-[22rem] max-w-full rounded" />
        <Skeleton className="h-4 w-[24rem] max-w-full rounded" />
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
