"use client";

import { ColumnDef } from "@tanstack/react-table";

import { getStandaloneFindingColumns } from "@/components/findings/table/column-standalone-findings";
import { FindingProps } from "@/types";

export const ColumnLatestFindings: ColumnDef<FindingProps>[] =
  getStandaloneFindingColumns({
    includeUpdatedAt: true,
  });
