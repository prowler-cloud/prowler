"use client";

import { useCallback, useEffect, useState } from "react";

import { getScans } from "@/actions/scans";
import { AutoRefresh } from "@/components/scans";
import { DataTable } from "@/components/ui/table";
import { MetaDataProps, ScanProps, SearchParamsProps } from "@/types";

import { ColumnGetScans } from "./column-get-scans";

export const SCAN_LAUNCHED_EVENT = "scan-launched";

interface ScansTableWithPollingProps {
  initialData: ScanProps[];
  initialMeta?: MetaDataProps;
  searchParams: SearchParamsProps;
}

const EXECUTING_STATES = ["executing", "available"] as const;

function expandScansWithProviderInfo(
  scans: ScanProps[],
  included?: Array<{ type: string; id: string; attributes: any }>,
) {
  return (
    scans?.map((scan) => {
      const providerId = scan.relationships?.provider?.data?.id;

      if (!providerId) {
        return { ...scan, providerInfo: undefined };
      }

      const providerData = included?.find(
        (item) => item.type === "providers" && item.id === providerId,
      );

      if (!providerData) {
        return { ...scan, providerInfo: undefined };
      }

      return {
        ...scan,
        providerInfo: {
          provider: providerData.attributes.provider,
          uid: providerData.attributes.uid,
          alias: providerData.attributes.alias,
        },
      };
    }) || []
  );
}

export function ScansTableWithPolling({
  initialData,
  initialMeta,
  searchParams,
}: ScansTableWithPollingProps) {
  const [scansData, setScansData] = useState<ScanProps[]>(initialData);
  const [meta, setMeta] = useState<MetaDataProps | undefined>(initialMeta);

  // Sync state with server data when props change (e.g., pagination or filter changes).
  // useState only uses its argument on first mount, so without this effect,
  // navigating to page 2 would change the URL but keep showing page 1 data.
  useEffect(() => {
    setScansData(initialData);
    setMeta(initialMeta);
  }, [initialData, initialMeta]);

  const hasExecutingScan = scansData.some((scan) =>
    EXECUTING_STATES.includes(
      scan.attributes.state as (typeof EXECUTING_STATES)[number],
    ),
  );

  const handleRefresh = useCallback(async () => {
    const page = parseInt(searchParams.page?.toString() || "1", 10);
    const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);
    const sort = searchParams.sort?.toString();

    const filters = Object.fromEntries(
      Object.entries(searchParams).filter(
        ([key]) => key.startsWith("filter[") && key !== "scanId",
      ),
    );

    const query = (filters["filter[search]"] as string) || "";

    const result = await getScans({
      query,
      page,
      sort,
      filters,
      pageSize,
      include: "provider",
    });

    if (result?.data) {
      const expanded = expandScansWithProviderInfo(
        result.data,
        result.included,
      );
      setScansData(expanded);

      if (result && "meta" in result) {
        setMeta(result.meta as MetaDataProps);
      }
    }
  }, [searchParams]);

  // Listen for scan launch events to trigger an immediate refresh
  useEffect(() => {
    const handler = () => {
      handleRefresh();
    };
    window.addEventListener(SCAN_LAUNCHED_EVENT, handler);
    return () => window.removeEventListener(SCAN_LAUNCHED_EVENT, handler);
  }, [handleRefresh]);

  return (
    <>
      <AutoRefresh
        hasExecutingScan={hasExecutingScan}
        onRefresh={handleRefresh}
      />
      <DataTable
        key={`scans-${scansData.length}-${meta?.pagination?.page}`}
        columns={ColumnGetScans}
        data={scansData}
        metadata={meta}
      />
    </>
  );
}
