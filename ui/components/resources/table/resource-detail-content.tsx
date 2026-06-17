"use client";

import { Row, RowSelectionState } from "@tanstack/react-table";
import { Container, CornerDownRight, Link } from "lucide-react";
import { useState } from "react";

import { FloatingMuteButton } from "@/components/findings/floating-mute-button";
import { FindingDetailDrawer } from "@/components/findings/table";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import {
  BreadcrumbNavigation,
  CustomBreadcrumbItem,
} from "@/components/shadcn";
import { DateWithTime } from "@/components/shadcn/entities/date-with-time";
import { EntityInfo } from "@/components/shadcn/entities/entity-info";
import {
  InfoField,
  InfoTooltip,
} from "@/components/shadcn/info-field/info-field";
import { LoadingState } from "@/components/shadcn/spinner/loading-state";
import { DataTable } from "@/components/shadcn/table";
import { EventsTimeline } from "@/components/shared/events-timeline/events-timeline";
import { ExternalResourceLink } from "@/components/shared/external-resource-link";
import { ResourceMetadataPanel } from "@/components/shared/resource-metadata-panel";
import { getGroupLabel } from "@/lib/categories";
import { getRegionFlag } from "@/lib/region-flags";
import { ProviderType, ResourceProps } from "@/types";

import {
  getResourceFindingsColumns,
  ResourceFinding,
} from "./resource-findings-columns";
import { useFindingDetails } from "./use-finding-details";
import { useResourceDrawerBootstrap } from "./use-resource-drawer-bootstrap";

const renderValue = (value: string | null | undefined) => {
  return value && value.trim() !== "" ? value : "-";
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
  const [findingsReloadNonce, setFindingsReloadNonce] = useState(0);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    null,
  );
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [activeTab, setActiveTab] = useState("findings");
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [searchQuery, setSearchQuery] = useState("");

  const resource = resourceDetails;
  const resourceId = resource.id;
  const attributes = resource.attributes;
  const providerData = resource.relationships.provider.data.attributes;
  const providerId = resource.relationships.provider.data.id;
  const {
    findingsData,
    findingsMetadata,
    findingsLoading,
    hasInitiallyLoaded,
    providerOrg,
    resourceTags,
  } = useResourceDrawerBootstrap({
    resourceId,
    resourceUid: attributes.uid,
    providerId,
    providerType: providerData.provider,
    currentPage,
    pageSize,
    searchQuery,
    findingsReloadNonce,
  });
  const {
    findingDetails,
    findingDetailLoading,
    navigateToFinding: loadFindingDetails,
    resetFindingDetails,
  } = useFindingDetails();

  const copyResourceUrl = () => {
    const url = `${window.location.origin}/resources?resourceId=${resourceId}`;
    navigator.clipboard.writeText(url);
  };

  const navigateToFinding = async (findingId: string) => {
    setSelectedFindingId(findingId);
    await loadFindingDetails(findingId);
  };

  const handleBackToResource = () => {
    setSelectedFindingId(null);
    resetFindingDetails();
  };

  const handleMuteComplete = (_findingIds?: string[]) => {
    const ids =
      _findingIds && _findingIds.length > 0 ? _findingIds : selectedFindingIds;

    setRowSelection({});
    if (ids.length > 0) setFindingsReloadNonce((v) => v + 1);
  };

  const failedFindings = findingsData;

  const selectableRowCount = failedFindings.filter(
    (f) => !f.attributes.muted,
  ).length;

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
          <LoadingState label="Loading finding details..." />
        ) : (
          findingDetails && (
            <FindingDetailDrawer
              key={findingDetails.id}
              finding={findingDetails}
              inline
              onMuteComplete={handleMuteComplete}
            />
          )
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
          </div>
          <ExternalResourceLink
            providerType={providerData.provider}
            resourceUid={attributes.uid}
            providerUid={providerData.uid}
            resourceName={attributes.name}
            region={attributes.region}
            className="justify-start self-start"
          />
        </div>
      </div>

      <div className="border-border-neutral-secondary bg-bg-neutral-secondary flex min-h-0 flex-1 flex-col gap-4 overflow-hidden rounded-lg border p-4">
        <div className="grid min-w-0 grid-cols-2 gap-4 md:grid-cols-4 md:gap-x-8 md:gap-y-4">
          {providerOrg ? (
            <div className="col-span-2 flex flex-col gap-1">
              <EntityInfo
                cloudProvider="aws"
                entityAlias={providerOrg.attributes.name}
                entityId={providerOrg.attributes.external_id}
              />
              <div className="flex items-start pl-6">
                <CornerDownRight className="text-text-neutral-tertiary mt-1 mr-2 size-4 shrink-0" />
                <EntityInfo
                  cloudProvider="aws"
                  entityAlias={providerData.alias ?? undefined}
                  entityId={providerData.uid}
                />
              </div>
            </div>
          ) : (
            <div className="col-span-2 md:col-span-1">
              <EntityInfo
                cloudProvider={providerData.provider as ProviderType}
                entityAlias={providerData.alias ?? undefined}
                entityId={providerData.uid}
              />
            </div>
          )}
          <div
            className={
              providerOrg
                ? "col-span-2 self-end md:col-span-1"
                : "col-span-2 md:col-span-1"
            }
          >
            <EntityInfo
              nameIcon={<Container className="size-4" />}
              entityAlias={resourceName}
              entityId={attributes.uid}
            />
          </div>
          <InfoField
            label="Service"
            variant="compact"
            className={providerOrg ? "self-end" : undefined}
          >
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

          <InfoField
            label="Created At"
            variant="compact"
            className="col-start-1 min-w-0"
          >
            <DateWithTime inline dateTime={attributes.inserted_at || "-"} />
          </InfoField>
          <InfoField
            label="Last Updated"
            variant="compact"
            className="col-start-2 min-w-0"
          >
            <DateWithTime inline dateTime={attributes.updated_at || "-"} />
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
              <TabsTrigger value="metadata" tooltip="Resource Metadata">
                Evidence
              </TabsTrigger>
              <TabsTrigger value="tags" tooltip="Tags">
                Tags
              </TabsTrigger>
              <TabsTrigger value="events" tooltip="Events">
                Events
              </TabsTrigger>
            </TabsList>
          </div>

          <div className="minimal-scrollbar min-h-0 flex-1 overflow-y-auto">
            <TabsContent value="findings" className="flex flex-col gap-4">
              {findingsLoading && !hasInitiallyLoaded ? (
                <LoadingState label="Loading findings..." />
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
                      setRowSelection({});
                      setSearchQuery(value);
                      setCurrentPage(1);
                    }}
                    controlledPage={currentPage}
                    controlledPageSize={pageSize}
                    onPageChange={(page) => {
                      setRowSelection({});
                      setCurrentPage(page);
                    }}
                    onPageSizeChange={(size) => {
                      setRowSelection({});
                      setCurrentPage(1);
                      setPageSize(size);
                    }}
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

            <TabsContent
              value="metadata"
              className="flex min-h-0 flex-1 flex-col gap-4 overflow-hidden"
            >
              <ResourceMetadataPanel
                metadata={attributes.metadata}
                details={attributes.details}
              />
            </TabsContent>

            <TabsContent value="tags" className="flex flex-col gap-4">
              {hasTags ? (
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  {tagEntries.map(([key, value]) => (
                    <InfoField key={key} label={key} variant="compact">
                      {renderValue(value)}
                    </InfoField>
                  ))}
                </div>
              ) : (
                <p className="text-text-neutral-tertiary py-8 text-center text-sm">
                  No tags available for this resource.
                </p>
              )}
            </TabsContent>

            <TabsContent value="events" className="flex flex-col gap-4">
              {activeTab === "events" && (
                <EventsTimeline
                  resourceId={resourceId}
                  isAwsProvider={providerData.provider === "aws"}
                />
              )}
            </TabsContent>
          </div>
        </Tabs>
      </div>
    </div>
  );
};
