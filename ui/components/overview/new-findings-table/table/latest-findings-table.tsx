"use client";

import { useRouter } from "next/navigation";
import type { ReactNode } from "react";

import {
  loadFindingTriageDetail,
  loadLatestFindingTriageNote,
} from "@/actions/findings";
import { getStandaloneFindingColumns } from "@/components/findings/table/column-standalone-findings";
import { DataTable } from "@/components/shadcn/table";
import { updateFindingTriageOrThrow } from "@/lib/finding-triage-update";
import type { FindingProps } from "@/types";
import type { FindingTriageUpdateHandler } from "@/types/findings-triage";

interface LatestFindingsTableProps {
  data: FindingProps[];
  header: ReactNode;
}

export function LatestFindingsTable({
  data,
  header,
}: LatestFindingsTableProps) {
  const router = useRouter();

  const handleTriageUpdate: FindingTriageUpdateHandler = async (input) => {
    const result = await updateFindingTriageOrThrow(input);
    router.refresh();
    return result;
  };

  const columns = getStandaloneFindingColumns({
    includeUpdatedAt: true,
    onTriageUpdateAction: handleTriageUpdate,
    onTriageNoteLoadAction: loadLatestFindingTriageNote,
    onTriageDetailLoadAction: loadFindingTriageDetail,
  });

  return <DataTable columns={columns} data={data} header={header} />;
}
