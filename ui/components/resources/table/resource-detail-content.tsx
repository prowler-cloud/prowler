"use client";

import { Row, RowSelectionState } from "@tanstack/react-table";
import { Check, Copy, ExternalLink, Link, Loader2 } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { getFindingById, getLatestFindings } from "@/actions/findings";
import { getResourceById } from "@/actions/resources";
import { FloatingMuteButton } from "@/components/findings/floating-mute-button";
import { FindingDetail } from "@/components/findings/table/finding-detail";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import { BreadcrumbNavigation, CustomBreadcrumbItem } from "@/components/ui";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import {
  DateWithTime,
  getProviderLogo,
  InfoField,
} from "@/components/ui/entities";
import { DataTable } from "@/components/ui/table";
import { createDict } from "@/lib";
import { getGroupLabel } from "@/lib/categories";
import { buildGitFileUrl } from "@/lib/iac-utils";
import {
  FindingProps,
  MetaDataProps,
  ProviderType,
  ResourceProps,
} from "@/types";

import {
  getResourceFindingsColumns,
  ResourceFinding,
} from "./resource-findings-columns";

const renderValue = (value: string | null | undefined) => {
  return value && value.trim() !== "" ? value : "-";
};

const parseMetadata = (
  metadata: Record<string, unknown> | string | null | undefined,
): Record<string, unknown> | null => {
  if (!metadata) return null;

  if (typeof metadata === "string") {
    try {
      const parsed = JSON.parse(metadata);
      return typeof parsed === "object" && parsed !== null ? parsed : null;
    } catch {
      return null;
    }
  }

  // After the !metadata check above, metadata can only be object at this point
  // (null was already filtered, string was handled)
  if (typeof metadata === "object") {
    return metadata as Record<string, unknown>;
  }

  return null;
};

const buildCustomBreadcrumbs = (
  _resourceName: string,
  findingTitle?: string,
  onBackToResource?: () => void,
): CustomBreadcrumbItem[] => {
  const breadcrumbs: CustomBreadcrumbItem[] = [
    {
      name: "Resource Details",
      isClickable: !!findingTitle,
      onClick: findingTitle ? onBackToResource : undefined,
      isLast: !findingTitle,
    },
  ];

  if (findingTitle) {
    breadcrumbs.push({
      name: findingTitle,
      isLast: true,
      isClickable: false,
    });
  }

  return breadcrumbs;
};

interface ResourceDetailContentProps {
  resourceDetails: ResourceProps;
}

/**
 * Heavy content component that contains all the state and data fetching logic.
 * This component should only be mounted when the drawer is actually open.
 */
export const ResourceDetailContent = ({
  resourceDetails,
}: ResourceDetailContentProps) => {
  const [findingsData, setFindingsData] = useState<ResourceFinding[]>([]);
  const [findingsMetadata, setFindingsMetadata] =
    useState<MetaDataProps | null>(null);
  const [resourceTags, setResourceTags] = useState<Record<string, string>>({});
  const [findingsLoading, setFindingsLoading] = useState(true);
  const [hasInitiallyLoaded, setHasInitiallyLoaded] = useState(false);
  const [findingsReloadNonce, setFindingsReloadNonce] = useState(0);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    null,
  );
  const [findingDetails, setFindingDetails] = useState<FindingProps | null>(
    null,
  );
  const [findingDetailLoading, setFindingDetailLoading] = useState(false);
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [activeTab, setActiveTab] = useState("overview");
  const [metadataCopied, setMetadataCopied] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [searchQuery, setSearchQuery] = useState("");
  const findingFetchRef = useRef<AbortController | null>(null);
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const resource = resourceDetails;
  const resourceId = resource.id;
  const attributes = resource.attributes;
  const providerData = resource.relationships.provider.data.attributes;

  // Cleanup abort controller on unmount
  useEffect(() => {
    return () => {
      findingFetchRef.current?.abort();
    };
  }, []);

  const copyResourceUrl = () => {
    const params = new URLSearchParams(searchParams.toString());
    params.set("resourceId", resourceId);
    const url = `${window.location.origin}${pathname}?${params.toString()}`;
    navigator.clipboard.writeText(url);
  };

  const copyMetadata = async (metadata: Record<string, unknown>) => {
    await navigator.clipboard.writeText(JSON.stringify(metadata, null, 2));
    setMetadataCopied(true);
    setTimeout(() => setMetadataCopied(false), 2000);
  };

  // Load resource tags on mount
  useEffect(() => {
    const loadResourceTags = async () => {
      try {
        const resourceData = await getResourceById(resourceId, {
          fields: ["tags"],
        });
        if (resourceData?.data) {
          setResourceTags(resourceData.data.attributes.tags || {});
        }
      } catch (err) {
        console.error("Error loading resource tags:", err);
        setResourceTags({});
      }
    };

    if (resourceId) {
      loadResourceTags();
    }
  }, [resourceId]);

  // Load findings with server-side pagination and search
  useEffect(() => {
    const loadFindings = async () => {
      setFindingsLoading(true);

      try {
        const findingsResponse = await getLatestFindings({
          page: currentPage,
          pageSize,
          query: searchQuery,
          sort: "severity,-inserted_at",
          filters: {
            "filter[resource_uid]": attributes.uid,
            "filter[status]": "FAIL",
          },
        });

        if (findingsResponse?.data) {
          setFindingsMetadata(findingsResponse.meta || null);
          setFindingsData(findingsResponse.data as ResourceFinding[]);
        } else {
          setFindingsData([]);
          setFindingsMetadata(null);
        }
      } catch (err) {
        console.error("Error loading findings:", err);
        setFindingsData([]);
        setFindingsMetadata(null);
      } finally {
        setFindingsLoading(false);
        setHasInitiallyLoaded(true);
      }
    };

    if (attributes.uid) {
      loadFindings();
    }
  }, [attributes.uid, currentPage, pageSize, searchQuery, findingsReloadNonce]);

  const navigateToFinding = async (findingId: string) => {
    if (findingFetchRef.current) {
      findingFetchRef.current.abort();
    }
    findingFetchRef.current = new AbortController();

    setSelectedFindingId(findingId);
    setFindingDetailLoading(true);

    try {
      const findingData = await getFindingById(
        findingId,
        "resources,scan.provider",
      );

      if (findingFetchRef.current?.signal.aborted) {
        return;
      }

      if (findingData?.data) {
        const resourceDict = createDict("resources", findingData);
        const scanDict = createDict("scans", findingData);
        const providerDict = createDict("providers", findingData);

        const finding = findingData.data;
        const scan = scanDict[finding.relationships?.scan?.data?.id];
        const foundResource =
          resourceDict[finding.relationships?.resources?.data?.[0]?.id];
        const provider = providerDict[scan?.relationships?.provider?.data?.id];

        const expandedFinding = {
          ...finding,
          relationships: { scan, resource: foundResource, provider },
        };

        setFindingDetails(expandedFinding);
      }
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        return;
      }
      console.error("Error fetching finding:", error);
    } finally {
      if (!findingFetchRef.current?.signal.aborted) {
        setFindingDetailLoading(false);
      }
    }
  };

  const handleBackToResource = () => {
    setSelectedFindingId(null);
    setFindingDetails(null);
    setFindingDetailLoading(false);
  };

  const handleMuteComplete = (_findingIds?: string[]) => {
    const ids =
      _findingIds && _findingIds.length > 0 ? _findingIds : selectedFindingIds;

    setRowSelection({});
    if (ids.length > 0) setFindingsReloadNonce((v) => v + 1);
    router.refresh();
  };

  const failedFindings = findingsData;

  const selectableRowCount = failedFindings.filter(
    (f) => !f.attributes.muted,
  ).length;

  // Reset selection when page changes
  useEffect(() => {
    setRowSelection({});
  }, [currentPage, pageSize]);

  const totalFindings = findingsMetadata?.pagination?.count || 0;

  const getRowCanSelect = (row: Row<ResourceFinding>): boolean =>
    !row.original.attributes.muted;

  const selectedFindingIds = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => failedFindings[parseInt(idx)]?.id)
    .filter(Boolean);

  const columns = getResourceFindingsColumns(
    rowSelection,
    selectableRowCount,
    navigateToFinding,
    handleMuteComplete,
  );

  const gitUrl =
    providerData.provider === "iac"
      ? buildGitFileUrl(
          providerData.uid,
          attributes.name,
          "",
          attributes.region,
        )
      : null;

  const findingTitle =
    findingDetails?.attributes?.check_metadata?.checktitle || "Finding Detail";

  // Content when viewing a finding detail (breadcrumb navigation)
  if (selectedFindingId) {
    return (
      <div className="flex flex-col gap-4">
        <BreadcrumbNavigation
          mode="custom"
          customItems={buildCustomBreadcrumbs(
            attributes.name,
            findingDetailLoading ? "Loading..." : findingTitle,
            handleBackToResource,
          )}
        />

        {findingDetailLoading ? (
          <div className="flex items-center justify-center gap-2 py-8">
            <Loader2 className="h-4 w-4 animate-spin" />
            <p className="text-text-neutral-secondary text-sm">
              Loading finding details...
            </p>
          </div>
        ) : (
          findingDetails && <FindingDetail findingDetails={findingDetails} />
        )}
      </div>
    );
  }

  // Main resource content
  return (
    <div className="flex min-w-0 flex-col gap-4 rounded-lg">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="shrink-0">
          {getProviderLogo(providerData.provider as ProviderType)}
        </div>

        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-text-neutral-primary line-clamp-2 text-lg leading-tight font-medium">
              {renderValue(attributes.name)}
            </h2>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={copyResourceUrl}
                  className="text-bg-data-info inline-flex cursor-pointer transition-opacity hover:opacity-80"
                  aria-label="Copy resource link to clipboard"
                >
                  <Link size={16} />
                </button>
              </TooltipTrigger>
              <TooltipContent>Copy resource link to clipboard</TooltipContent>
            </Tooltip>
            {providerData.provider === "iac" && gitUrl && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <a
                    href={gitUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-bg-data-info inline-flex items-center gap-1 text-sm"
                    aria-label="Open resource in repository"
                  >
                    <ExternalLink size={16} />
                    View in Repository
                  </a>
                </TooltipTrigger>
                <TooltipContent>
                  Go to Resource in the Repository
                </TooltipContent>
              </Tooltip>
            )}
          </div>

          <div className="text-text-neutral-tertiary text-sm">
            <span className="text-text-neutral-secondary mr-1">
              Last Updated:
            </span>
            <DateWithTime inline dateTime={attributes.updated_at || "-"} />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="mb-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="findings">
            Findings {totalFindings > 0 && `(${totalFindings})`}
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="flex flex-col gap-4">
          <InfoField label="Resource UID" variant="simple">
            <CodeSnippet value={attributes.uid} className="max-w-full" />
          </InfoField>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoField label="Name">{renderValue(attributes.name)}</InfoField>
            <InfoField label="Type">{renderValue(attributes.type)}</InfoField>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoField label="Group">
              {attributes.groups && attributes.groups.length > 0
                ? attributes.groups.map(getGroupLabel).join(", ")
                : "-"}
            </InfoField>
            <InfoField label="Service">
              {renderValue(attributes.service)}
            </InfoField>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoField label="Region">
              {renderValue(attributes.region)}
            </InfoField>
            <InfoField label="Partition">
              {renderValue(attributes.partition)}
            </InfoField>
          </div>
          <InfoField label="Details" variant="simple">
            {renderValue(attributes.details)}
          </InfoField>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoField label="Created At">
              <DateWithTime inline dateTime={attributes.inserted_at} />
            </InfoField>
            <InfoField label="Last Updated">
              <DateWithTime inline dateTime={attributes.updated_at} />
            </InfoField>
          </div>

          {(() => {
            const parsedMetadata = parseMetadata(attributes.metadata);
            return parsedMetadata &&
              Object.entries(parsedMetadata).length > 0 ? (
              <InfoField label="Metadata" variant="simple">
                <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary relative w-full rounded-lg border">
                  <button
                    type="button"
                    onClick={() => copyMetadata(parsedMetadata)}
                    className="text-text-neutral-secondary hover:text-text-neutral-primary absolute top-2 right-2 z-10 cursor-pointer transition-colors"
                    aria-label="Copy metadata to clipboard"
                  >
                    {metadataCopied ? (
                      <Check className="h-4 w-4" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </button>
                  <pre className="minimal-scrollbar mr-10 max-h-[200px] overflow-auto p-3 text-xs break-words whitespace-pre-wrap">
                    {JSON.stringify(parsedMetadata, null, 2)}
                  </pre>
                </div>
              </InfoField>
            ) : null;
          })()}

          {resourceTags && Object.entries(resourceTags).length > 0 ? (
            <div className="flex flex-col gap-4">
              <h4 className="text-text-neutral-secondary text-sm font-bold">
                Tags
              </h4>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                {Object.entries(resourceTags).map(([key, value]) => (
                  <InfoField key={key} label={key}>
                    {renderValue(value)}
                  </InfoField>
                ))}
              </div>
            </div>
          ) : null}
        </TabsContent>

        {/* Findings Tab */}
        <TabsContent value="findings" className="flex flex-col gap-4">
          {findingsLoading && !hasInitiallyLoaded ? (
            <div className="flex items-center justify-center gap-2 py-8">
              <Loader2 className="h-4 w-4 animate-spin" />
              <p className="text-text-neutral-secondary text-sm">
                Loading findings...
              </p>
            </div>
          ) : (
            <>
              <DataTable
                columns={columns}
                data={failedFindings}
                metadata={findingsMetadata ?? undefined}
                showSearch
                disableScroll
                enableRowSelection
                rowSelection={rowSelection}
                onRowSelectionChange={setRowSelection}
                getRowCanSelect={getRowCanSelect}
                controlledSearch={searchQuery}
                onSearchChange={(value) => {
                  setSearchQuery(value);
                  setCurrentPage(1);
                }}
                controlledPage={currentPage}
                controlledPageSize={pageSize}
                onPageChange={setCurrentPage}
                onPageSizeChange={setPageSize}
                isLoading={findingsLoading}
              />
              {selectedFindingIds.length > 0 && (
                <FloatingMuteButton
                  selectedCount={selectedFindingIds.length}
                  selectedFindingIds={selectedFindingIds}
                  onComplete={handleMuteComplete}
                />
              )}
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};
