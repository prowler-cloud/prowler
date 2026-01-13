"use client";

import { Row, RowSelectionState } from "@tanstack/react-table";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { DataTable } from "@/components/ui/table";
import { FindingProps, MetaDataProps } from "@/types";

import { FloatingMuteButton } from "../floating-mute-button";
import { getColumnFindings } from "./column-findings";
import { FindingsSelectionContext } from "./findings-selection-context";

interface FindingsTableWithSelectionProps {
  data: FindingProps[];
  metadata?: MetaDataProps;
}

export function FindingsTableWithSelection({
  data,
  metadata,
}: FindingsTableWithSelectionProps) {
  const router = useRouter();
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});

  // Track the finding IDs to detect when data changes (e.g., after muting)
  const currentFindingIds = (data ?? []).map((f) => f.id).join(",");
  const previousFindingIdsRef = useRef(currentFindingIds);

  // Reset selection when page changes
  useEffect(() => {
    setRowSelection({});
  }, [metadata?.pagination?.page]);

  // Reset selection when the data changes (e.g., after muting a finding)
  // This prevents the wrong findings from appearing selected after refresh
  useEffect(() => {
    if (previousFindingIdsRef.current !== currentFindingIds) {
      setRowSelection({});
      previousFindingIdsRef.current = currentFindingIds;
    }
  }, [currentFindingIds]);

  // Ensure data is always an array for safe operations
  const safeData = data ?? [];

  // Get selected finding IDs and data (only non-muted findings can be selected)
  const selectedFindingIds = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => safeData[parseInt(idx)]?.id)
    .filter(Boolean);

  const selectedFindings = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => safeData[parseInt(idx)])
    .filter(Boolean);

  // Count of selectable rows (non-muted findings only)
  const selectableRowCount = safeData.filter((f) => !f.attributes.muted).length;

  // Function to determine if a row can be selected (muted findings cannot be selected)
  const getRowCanSelect = (row: Row<FindingProps>): boolean => {
    return !row.original.attributes.muted;
  };

  const clearSelection = () => {
    setRowSelection({});
  };

  const isSelected = (id: string) => {
    return selectedFindingIds.includes(id);
  };

  // Handle mute completion: clear selection and refresh data
  const handleMuteComplete = () => {
    clearSelection();
    router.refresh();
  };

  // Generate columns with access to rowSelection state and selectable row count
  const columns = getColumnFindings(rowSelection, selectableRowCount);

  return (
    <FindingsSelectionContext.Provider
      value={{
        selectedFindingIds,
        selectedFindings,
        clearSelection,
        isSelected,
      }}
    >
      <DataTable
        columns={columns}
        data={safeData}
        metadata={metadata}
        enableRowSelection
        rowSelection={rowSelection}
        onRowSelectionChange={setRowSelection}
        getRowCanSelect={getRowCanSelect}
        showSearch
      />

      {selectedFindingIds.length > 0 && (
        <FloatingMuteButton
          selectedCount={selectedFindingIds.length}
          selectedFindingIds={selectedFindingIds}
          onComplete={handleMuteComplete}
        />
      )}
    </FindingsSelectionContext.Provider>
  );
}
