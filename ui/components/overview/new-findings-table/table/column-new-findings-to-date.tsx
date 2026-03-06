"use client";

import { ColumnDef, RowSelectionState } from "@tanstack/react-table";

import { getColumnFindings } from "@/components/findings/table/column-findings";
import { FindingProps } from "@/types";

const baseColumns: ColumnDef<FindingProps>[] = getColumnFindings(
  {} as RowSelectionState,
  0,
).filter((column) => column.id !== "select" && column.id !== "actions");

export const ColumnNewFindingsToDate: ColumnDef<FindingProps>[] = baseColumns;
