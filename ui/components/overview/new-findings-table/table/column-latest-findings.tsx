"use client";

import { ColumnDef } from "@tanstack/react-table";

import {
  loadLatestFindingTriageNote,
  updateFindingTriage,
} from "@/actions/findings";
import { getStandaloneFindingColumns } from "@/components/findings/table/column-standalone-findings";
import { FindingProps } from "@/types";

export const ColumnLatestFindings: ColumnDef<FindingProps>[] =
  getStandaloneFindingColumns({
    includeUpdatedAt: true,
    onTriageUpdateAction: async (input) => {
      await updateFindingTriage(input);
    },
    onTriageNoteLoadAction: loadLatestFindingTriageNote,
  });
