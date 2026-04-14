"use client";

import { Row, RowSelectionState } from "@tanstack/react-table";
import {
  Check,
  Container,
  Copy,
  ExternalLink,
  Link,
  Loader2,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { getFindingById, getLatestFindings } from "@/actions/findings";
import { getResourceById } from "@/actions/resources";
import { FloatingMuteButton } from "@/components/findings/floating-mute-button";
import { FindingDetail } from "@/components/findings/table/finding-detail";
import {
  Card,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import {
  InfoField,
  InfoTooltip,
} from "@/components/shadcn/info-field/info-field";
import { EventsTimeline } from "@/components/shared/events-timeline/events-timeline";
import { BreadcrumbNavigation, CustomBreadcrumbItem } from "@/components/ui";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import { EntityInfo } from "@/components/ui/entities/entity-info";
import { DataTable } from "@/components/ui/table";
import { createDict } from "@/lib";
import { getGroupLabel } from "@/lib/categories";
import { buildGitFileUrl } from "@/lib/iac-utils";
import { getRegionFlag } from "@/lib/region-flags";
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
  const [activeTab, setActiveTab] = useState("findings");
  const [metadataCopied, setMetadataCopied] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [searchQuery, setSearchQuery] = useState("");
  const findingFetchRef = useRef<AbortController | null>(null);
  const router = useRouter();

  const resource = resourceDetails;
  const resourceId = resource.id;
  const attributes = resource.attributes;
  const providerData = resource.relationships.provider.data.attributes;

  // Reset to overview tab when switching resources
  useEffect(() => {
    setActiveTab("findings");
  }, [resourceId]);

  // Cleanup abort controller on unmount
  useEffect(() => {
    return () => {
      findingFetchRef.current?.abort();
    };
  }, []);

  const copyResourceUrl = () => {
    const url = `${window.location.origin}/resources?resourceId=${resourceId}`;
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
  const resourceName =
    typeof attributes.name === "string" && attributes.name.trim().length > 0
      ? attributes.name
      : "Unnamed resource";
  const resourceRegion = renderValue(attributes.region);
  const regionFlag = getRegionFlag(resourceRegion);
  const groupValue =
    attributes.groups && attributes.groups.length > 0
      ? attributes.groups.map(getGroupLabel).join(", ")
      : "-";
  const parsedMetadata = parseMetadata(attributes.metadata);
  const hasMetadata =
    parsedMetadata !== null && Object.entries(parsedMetadata).length > 0;
  const tagEntries = Object.entries(resourceTags);
  const hasTags = tagEntries.length > 0;

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
    <div className="flex h-full min-w-0 flex-col gap-4 overflow-hidden">
      <div className="flex flex-col gap-2">
        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-text-neutral-primary line-clamp-2 text-lg leading-tight font-medium">
              {resourceName}
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
        </div>
      </div>

      <div className="border-border-neutral-secondary bg-bg-neutral-secondary flex min-h-0 flex-1 flex-col gap-4 overflow-hidden rounded-lg border p-4">
        <div className="grid min-w-0 grid-cols-1 gap-4 md:grid-cols-4 md:gap-x-8 md:gap-y-4">
          <EntityInfo
            cloudProvider={providerData.provider as ProviderType}
            entityAlias={providerData.alias ?? undefined}
            entityId={providerData.uid}
          />
          <EntityInfo
            nameIcon={<Container className="size-4" />}
            entityAlias={resourceName}
            entityId={attributes.uid}
          />
          <InfoField label="Service" variant="compact">
            {renderValue(attributes.service)}
          </InfoField>
          <InfoField label="Region" variant="compact">
            <span className="flex items-center gap-1.5">
              {regionFlag && (
                <span className="translate-y-px text-base leading-none">
                  {regionFlag}
                </span>
              )}
              {resourceRegion}
            </span>
          </InfoField>

          <InfoField label="Type" variant="compact">
            {renderValue(attributes.type)}
          </InfoField>
          <InfoField label="Group" variant="compact">
            {groupValue}
          </InfoField>
          <InfoField label="Partition" variant="compact">
            {renderValue(attributes.partition)}
          </InfoField>
          <InfoField label="Resource UID" variant="compact">
            <CodeSnippet
              value={attributes.uid}
              transparent
              className="max-w-full text-sm"
            />
          </InfoField>

          <InfoField label="Created At" variant="compact">
            <DateWithTime inline dateTime={attributes.inserted_at || "-"} />
          </InfoField>
          <InfoField label="Last Updated" variant="compact">
            <DateWithTime inline dateTime={attributes.updated_at || "-"} />
          </InfoField>
          <InfoField label="Failed Findings" variant="compact">
            {String(attributes.failed_findings_count ?? 0)}
          </InfoField>
        </div>

        <Tabs
          value={activeTab}
          onValueChange={setActiveTab}
          className="mt-2 flex min-h-0 w-full flex-1 flex-col"
        >
          <div className="mb-4 flex shrink-0 items-center justify-between">
            <TabsList>
              <TabsTrigger value="findings">
                <span className="flex items-center gap-1">
                  Findings {totalFindings > 0 && `(${totalFindings})`}
                  <InfoTooltip content="This table also includes muted findings" />
                </span>
              </TabsTrigger>
              <TabsTrigger value="metadata">Metadata</TabsTrigger>
              <TabsTrigger value="tags">Tags</TabsTrigger>
              <TabsTrigger value="events">Events</TabsTrigger>
            </TabsList>
          </div>

          <div className="minimal-scrollbar min-h-0 flex-1 overflow-y-auto">
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

            <TabsContent value="metadata" className="flex flex-col gap-4">
              {attributes.details && attributes.details.trim() !== "" && (
                <Card variant="inner">
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-sm font-semibold">
                      Details:
                    </span>
                    <p className="text-text-neutral-primary text-sm break-words whitespace-pre-wrap">
                      {attributes.details}
                    </p>
                  </div>
                </Card>
              )}

              {hasMetadata && parsedMetadata && (
                <Card variant="inner">
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-sm font-semibold">
                      Metadata:
                    </span>
                    <div className="border-border-neutral-secondary bg-bg-neutral-secondary relative w-full rounded-lg border">
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
                  </div>
                </Card>
              )}

              {!attributes.details?.trim() && !hasMetadata && (
                <p className="text-text-neutral-tertiary py-8 text-center text-sm">
                  No metadata available for this resource.
                </p>
              )}
            </TabsContent>

            <TabsContent value="tags" className="flex flex-col gap-4">
              {hasTags ? (
                <Card variant="inner">
                  <div className="flex flex-col gap-3">
                    <span className="text-text-neutral-secondary text-sm font-semibold">
                      Tags:
                    </span>
                    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                      {tagEntries.map(([key, value]) => (
                        <InfoField key={key} label={key} variant="compact">
                          {renderValue(value)}
                        </InfoField>
                      ))}
                    </div>
                  </div>
                </Card>
              ) : (
                <p className="text-text-neutral-tertiary py-8 text-center text-sm">
                  No tags available for this resource.
                </p>
              )}
            </TabsContent>

            <TabsContent value="events" className="flex flex-col gap-4">
              <EventsTimeline
                resourceId={resourceId}
                isAwsProvider={providerData.provider === "aws"}
              />
            </TabsContent>
          </div>
        </Tabs>
      </div>
    </div>
  );
};
