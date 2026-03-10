"use client";

import { ExternalLink, Link, X } from "lucide-react";
import { usePathname, useSearchParams } from "next/navigation";
import type { ReactNode } from "react";
import ReactMarkdown from "react-markdown";

import {
  Drawer,
  DrawerClose,
  DrawerContent,
  DrawerDescription,
  DrawerHeader,
  DrawerTitle,
  DrawerTrigger,
  InfoField,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { EntityInfo } from "@/components/ui/entities";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import { SeverityBadge } from "@/components/ui/table/severity-badge";
import {
  FindingStatus,
  StatusFindingBadge,
} from "@/components/ui/table/status-finding-badge";
import { buildGitFileUrl, extractLineRangeFromUid } from "@/lib/iac-utils";
import { cn } from "@/lib/utils";
import { FindingProps, ProviderType } from "@/types";

import { Muted } from "../muted";
import { DeltaIndicator } from "./delta-indicator";

const MarkdownContainer = ({ children }: { children: string }) => {
  return (
    <div className="prose prose-sm dark:prose-invert max-w-none break-words whitespace-normal">
      <ReactMarkdown>{children}</ReactMarkdown>
    </div>
  );
};

const renderValue = (value: string | null | undefined) => {
  return value && value.trim() !== "" ? value : "-";
};

// Add new utility function for duration formatting
const formatDuration = (seconds: number) => {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = seconds % 60;

  const parts = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (remainingSeconds > 0 || parts.length === 0)
    parts.push(`${remainingSeconds}s`);

  return parts.join(" ");
};

interface FindingDetailProps {
  findingDetails: FindingProps;
  trigger?: ReactNode;
  open?: boolean;
  defaultOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
}

export const FindingDetail = ({
  findingDetails,
  trigger,
  open,
  defaultOpen = false,
  onOpenChange,
}: FindingDetailProps) => {
  const finding = findingDetails;
  const attributes = finding.attributes;
  const resource = finding.relationships.resource.attributes;
  const scan = finding.relationships.scan.attributes;
  const providerDetails = finding.relationships.provider.attributes;
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const copyFindingUrl = () => {
    const params = new URLSearchParams(searchParams.toString());
    params.set("id", findingDetails.id);
    const url = `${window.location.origin}${pathname}?${params.toString()}`;
    navigator.clipboard.writeText(url);
  };

  // Build Git URL for IaC findings
  const gitUrl =
    providerDetails.provider === "iac"
      ? buildGitFileUrl(
          providerDetails.uid,
          resource.name,
          extractLineRangeFromUid(attributes.uid) || "",
          resource.region,
        )
      : null;

  const content = (
    <div className="flex min-w-0 flex-col gap-4 rounded-lg">
      {/* Header */}
      <div className="flex flex-col gap-2">
        {/* Row 1: Status badges */}
        <div className="flex flex-wrap items-center gap-4">
          <StatusFindingBadge status={attributes.status as FindingStatus} />
          <SeverityBadge severity={attributes.severity || "-"} />
          {attributes.delta && (
            <div className="flex items-center gap-1 capitalize">
              <DeltaIndicator delta={attributes.delta} />
              <span className="text-text-neutral-secondary text-xs">
                {attributes.delta}
              </span>
            </div>
          )}
          <Muted
            isMuted={attributes.muted}
            mutedReason={attributes.muted_reason || ""}
          />
        </div>

        {/* Row 2: Title with copy link */}
        <h2 className="text-text-neutral-primary line-clamp-2 flex items-center gap-2 text-lg leading-tight font-medium">
          {renderValue(attributes.check_metadata.checktitle)}
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                onClick={copyFindingUrl}
                className="text-bg-data-info inline-flex cursor-pointer transition-opacity hover:opacity-80"
                aria-label="Copy finding link to clipboard"
              >
                <Link size={16} />
              </button>
            </TooltipTrigger>
            <TooltipContent>Copy finding link to clipboard</TooltipContent>
          </Tooltip>
        </h2>

        {/* Row 3: First Seen */}
        <div className="text-text-neutral-tertiary text-sm">
          <span className="text-text-neutral-secondary mr-1">Time:</span>
          <DateWithTime inline dateTime={attributes.updated_at || "-"} />
        </div>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="general" className="w-full">
        <TabsList className="mb-4">
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="resources">Resources</TabsTrigger>
          <TabsTrigger value="scans">Scans</TabsTrigger>
        </TabsList>

        <p className="text-text-neutral-primary mb-4 text-sm">
          Here is an overview of this finding:
        </p>

        {/* General Tab */}
        <TabsContent value="general" className="flex flex-col gap-4">
          <div className="flex flex-wrap gap-4">
            <EntityInfo
              cloudProvider={providerDetails.provider as ProviderType}
              entityAlias={providerDetails.alias}
              entityId={providerDetails.uid}
              showConnectionStatus={providerDetails.connection.connected}
            />
            <InfoField label="Service">
              {attributes.check_metadata.servicename}
            </InfoField>
            <InfoField label="Region">{resource.region}</InfoField>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            <InfoField label="Check ID" variant="simple">
              <CodeSnippet value={attributes.check_id} className="max-w-full" />
            </InfoField>
            <InfoField label="Finding ID" variant="simple">
              <CodeSnippet value={findingDetails.id} className="max-w-full" />
            </InfoField>
            <InfoField label="Finding UID" variant="simple">
              <CodeSnippet value={attributes.uid} className="max-w-full" />
            </InfoField>
            <InfoField label="First seen" variant="simple">
              <DateWithTime inline dateTime={attributes.first_seen_at || "-"} />
            </InfoField>
          </div>

          {attributes.status === "FAIL" && (
            <InfoField label="Risk" variant="simple">
              <div
                className={cn(
                  "max-w-full rounded-md border p-2",
                  "border-border-error-primary bg-bg-fail-secondary",
                )}
              >
                <MarkdownContainer>
                  {attributes.check_metadata.risk}
                </MarkdownContainer>
              </div>
            </InfoField>
          )}

          <InfoField label="Description">
            <MarkdownContainer>
              {attributes.check_metadata.description}
            </MarkdownContainer>
          </InfoField>

          <InfoField label="Status Extended">
            {renderValue(attributes.status_extended)}
          </InfoField>

          {attributes.check_metadata.remediation && (
            <div className="flex flex-col gap-4">
              <h4 className="text-text-neutral-primary text-sm font-bold">
                Remediation Details
              </h4>

              {/* Recommendation section */}
              {attributes.check_metadata.remediation.recommendation.text && (
                <InfoField label="Recommendation">
                  <div className="flex flex-col gap-2">
                    <MarkdownContainer>
                      {
                        attributes.check_metadata.remediation.recommendation
                          .text
                      }
                    </MarkdownContainer>

                    {attributes.check_metadata.remediation.recommendation
                      .url && (
                      <CustomLink
                        href={
                          attributes.check_metadata.remediation.recommendation
                            .url
                        }
                        size="sm"
                      >
                        Learn more
                      </CustomLink>
                    )}
                  </div>
                </InfoField>
              )}

              {/* CLI Command section */}
              {attributes.check_metadata.remediation.code.cli && (
                <InfoField label="CLI Command" variant="simple">
                  <div
                    className={cn("rounded-md p-2", "bg-bg-neutral-tertiary")}
                  >
                    <span className="text-xs whitespace-pre-line">
                      {attributes.check_metadata.remediation.code.cli}
                    </span>
                  </div>
                </InfoField>
              )}

              {/* Remediation Steps section */}
              {attributes.check_metadata.remediation.code.other && (
                <InfoField label="Remediation Steps">
                  <MarkdownContainer>
                    {attributes.check_metadata.remediation.code.other}
                  </MarkdownContainer>
                </InfoField>
              )}

              {/* Additional URLs section */}
              {attributes.check_metadata.additionalurls &&
                attributes.check_metadata.additionalurls.length > 0 && (
                  <InfoField label="References">
                    <ul className="list-inside list-disc space-y-1">
                      {attributes.check_metadata.additionalurls.map(
                        (link, idx) => (
                          <li key={idx}>
                            <CustomLink
                              href={link}
                              size="sm"
                              className="break-all whitespace-normal!"
                            >
                              {link}
                            </CustomLink>
                          </li>
                        ),
                      )}
                    </ul>
                  </InfoField>
                )}
            </div>
          )}

          <InfoField label="Categories">
            {attributes.check_metadata.categories?.join(", ") || "none"}
          </InfoField>
        </TabsContent>

        {/* Resources Tab */}
        <TabsContent value="resources" className="flex flex-col gap-4">
          {providerDetails.provider === "iac" && gitUrl && (
            <div className="flex justify-end">
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
            </div>
          )}

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoField label="Resource Name">
              {renderValue(resource.name)}
            </InfoField>
            <InfoField label="Resource Type">
              {renderValue(resource.type)}
            </InfoField>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoField label="Service">
              {renderValue(resource.service)}
            </InfoField>
            <InfoField label="Region">{renderValue(resource.region)}</InfoField>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoField label="Partition">
              {renderValue(resource.partition)}
            </InfoField>
            <InfoField label="Details">
              {renderValue(resource.details)}
            </InfoField>
          </div>

          <InfoField label="Resource ID" variant="simple">
            <CodeSnippet value={resource.uid} />
          </InfoField>

          {resource.tags && Object.entries(resource.tags).length > 0 && (
            <div className="flex flex-col gap-4">
              <h4 className="text-text-neutral-secondary text-sm font-bold">
                Tags
              </h4>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                {Object.entries(resource.tags).map(([key, value]) => (
                  <InfoField key={key} label={key}>
                    {renderValue(value)}
                  </InfoField>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoField label="Created At">
              <DateWithTime inline dateTime={resource.inserted_at || "-"} />
            </InfoField>
            <InfoField label="Last Updated">
              <DateWithTime inline dateTime={resource.updated_at || "-"} />
            </InfoField>
          </div>
        </TabsContent>

        {/* Scans Tab */}
        <TabsContent value="scans" className="flex flex-col gap-4">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <InfoField label="Scan Name">{scan.name || "N/A"}</InfoField>
            <InfoField label="Resources Scanned">
              {scan.unique_resource_count}
            </InfoField>
            <InfoField label="Progress">{scan.progress}%</InfoField>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <InfoField label="Trigger">{scan.trigger}</InfoField>
            <InfoField label="State">{scan.state}</InfoField>
            <InfoField label="Duration">
              {formatDuration(scan.duration)}
            </InfoField>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoField label="Started At">
              <DateWithTime inline dateTime={scan.started_at || "-"} />
            </InfoField>
            <InfoField label="Completed At">
              <DateWithTime inline dateTime={scan.completed_at || "-"} />
            </InfoField>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoField label="Launched At">
              <DateWithTime inline dateTime={scan.inserted_at || "-"} />
            </InfoField>
            {scan.scheduled_at && (
              <InfoField label="Scheduled At">
                <DateWithTime inline dateTime={scan.scheduled_at} />
              </InfoField>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );

  // If no trigger, render content directly (inline mode)
  if (!trigger) {
    return content;
  }

  // With trigger, wrap in Drawer
  return (
    <Drawer
      direction="right"
      open={open}
      defaultOpen={defaultOpen}
      onOpenChange={onOpenChange}
    >
      <DrawerTrigger asChild>{trigger}</DrawerTrigger>
      <DrawerContent className="minimal-scrollbar 3xl:w-1/3 h-full w-full overflow-x-hidden overflow-y-auto p-6 md:w-1/2 md:max-w-none">
        <DrawerHeader className="sr-only">
          <DrawerTitle>Finding Details</DrawerTitle>
          <DrawerDescription>View the finding details</DrawerDescription>
        </DrawerHeader>
        <DrawerClose className="ring-offset-background focus:ring-ring absolute top-4 right-4 rounded-sm opacity-70 transition-opacity hover:opacity-100 focus:ring-2 focus:ring-offset-2 focus:outline-none">
          <X className="size-4" />
          <span className="sr-only">Close</span>
        </DrawerClose>
        {content}
      </DrawerContent>
    </Drawer>
  );
};
