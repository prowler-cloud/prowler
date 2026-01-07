import { Info } from "lucide-react";

import { getMuteRules } from "@/actions/mute-rules";
import { Card, Skeleton } from "@/components/shadcn";
import { SearchParamsProps } from "@/types/components";

import { MuteRulesTableClient } from "./mute-rules-table-client";

interface MuteRulesTableProps {
  searchParams: SearchParamsProps;
}

export async function MuteRulesTable({ searchParams }: MuteRulesTableProps) {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);
  const sort = searchParams.sort?.toString() || "-inserted_at";

  const muteRulesData = await getMuteRules({
    page,
    pageSize,
    sort,
  });

  const muteRules = muteRulesData?.data || [];

  if (muteRules.length === 0) {
    return (
      <Card variant="base" className="p-8">
        <div className="flex flex-col items-center justify-center gap-4 text-center">
          <div className="rounded-full bg-slate-100 p-4 dark:bg-slate-800">
            <Info className="size-8 text-slate-500" />
          </div>
          <div>
            <h3 className="text-lg font-medium text-slate-900 dark:text-white">
              No mute rules yet
            </h3>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
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
    <Card variant="base" className="p-6">
      <div className="mb-6">
        <h3 className="text-default-700 mb-2 text-lg font-semibold">
          Simple Mutelist Rules
        </h3>
        <ul className="text-default-600 list-disc pl-5 text-sm">
          <li>
            <strong>
              These rules take effect immediately on existing findings.
            </strong>
          </li>
          <li>
            Create rules by selecting findings from the Findings page and
            clicking &quot;Mute&quot;.
          </li>
          <li>Toggle rules on/off to enable or disable muting.</li>
        </ul>
      </div>
      <MuteRulesTableClient
        muteRules={muteRules}
        metadata={
          muteRulesData?.meta
            ? { ...muteRulesData.meta, version: "" }
            : undefined
        }
      />
    </Card>
  );
}

export function MuteRulesTableSkeleton() {
  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-lg border border-slate-200 dark:border-slate-800">
        <div className="border-b border-slate-200 p-4 dark:border-slate-800">
          <div className="flex gap-8">
            <Skeleton className="h-4 w-20" />
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-4 w-16" />
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-4 w-16" />
            <Skeleton className="h-4 w-16" />
          </div>
        </div>
        {[...Array(5)].map((_, i) => (
          <div
            key={i}
            className="flex items-center gap-8 border-b border-slate-200 p-4 last:border-0 dark:border-slate-800"
          >
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-4 w-40" />
            <Skeleton className="h-4 w-12" />
            <Skeleton className="h-4 w-28" />
            <Skeleton className="h-5 w-10" />
            <Skeleton className="size-8 rounded-full" />
          </div>
        ))}
      </div>
    </div>
  );
}
