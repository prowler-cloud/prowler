"use client";

import { Snippet } from "@heroui/snippet";
import { ExternalLink } from "lucide-react";
import ReactMarkdown from "react-markdown";

import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { CustomSection } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import {
  CopyLinkButton,
  EntityInfoShort,
  InfoField,
} from "@/components/ui/entities";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import { SeverityBadge } from "@/components/ui/table/severity-badge";
import { FindingProps, ProviderType } from "@/types";

import { Muted } from "../muted";
import { DeltaIndicator } from "./delta-indicator";
import { buildGitFileUrl, extractLineRangeFromUid } from "./git-utils";

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

export const FindingDetail = ({
  findingDetails,
}: {
  findingDetails: FindingProps;
}) => {
  const finding = findingDetails;
  const attributes = finding.attributes;
  const resource = finding.relationships.resource.attributes;
  const scan = finding.relationships.scan.attributes;
  const providerDetails = finding.relationships.provider.attributes;
  const currentUrl = new URL(window.location.href);
  const params = new URLSearchParams(currentUrl.search);
  params.set("id", findingDetails.id);
  const url = `${window.location.origin}${currentUrl.pathname}?${params.toString()}`;

  return (
    <div className="flex flex-col gap-6 rounded-lg">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="dark:text-prowler-theme-pale/90 line-clamp-2 text-lg leading-tight font-medium text-gray-800">
            {renderValue(attributes.check_metadata.checktitle)}
            <CopyLinkButton url={url} />
          </h2>
        </div>
        <div className="flex items-center gap-x-4">
          <Muted
            isMuted={attributes.muted}
            mutedReason={attributes.muted_reason || ""}
          />

          <div
            className={`rounded-lg px-3 py-1 text-sm font-semibold ${
              attributes.status === "PASS"
                ? "bg-green-100 text-green-600"
                : attributes.status === "MANUAL"
                  ? "bg-gray-100 text-gray-600"
                  : "text-system-severity-critical bg-red-100"
            }`}
          >
            {renderValue(attributes.status)}
          </div>
        </div>
      </div>

      {/* Check Metadata */}
      <CustomSection title="Finding Details">
        <div className="flex flex-wrap gap-4">
          <EntityInfoShort
            cloudProvider={providerDetails.provider as ProviderType}
            entityAlias={providerDetails.alias}
            entityId={providerDetails.uid}
            showConnectionStatus={providerDetails.connection.connected}
          />
          <InfoField label="Service">
            {attributes.check_metadata.servicename}
          </InfoField>
          <InfoField label="Region">{resource.region}</InfoField>
          <InfoField label="First Seen">
            <DateWithTime inline dateTime={attributes.first_seen_at || "-"} />
          </InfoField>
          {attributes.delta && (
            <InfoField
              label="Delta"
              tooltipContent="Indicates whether the finding is new (NEW), has changed status (CHANGED), or remains unchanged (NONE) compared to previous scans."
              className="capitalize"
            >
              <div className="flex items-center gap-2">
                <DeltaIndicator delta={attributes.delta} />
                {attributes.delta}
              </div>
            </InfoField>
          )}
          <InfoField label="Severity" variant="simple">
            <SeverityBadge severity={attributes.severity || "-"} />
          </InfoField>
        </div>
        <InfoField label="Finding ID" variant="simple">
          <CodeSnippet value={findingDetails.id} />
        </InfoField>
        <InfoField label="Check ID" variant="simple">
          <CodeSnippet value={attributes.check_id} />
        </InfoField>
        <InfoField label="Finding UID" variant="simple">
          <CodeSnippet value={attributes.uid} />
        </InfoField>

        {attributes.status === "FAIL" && (
          <InfoField label="Risk" variant="simple">
            <Snippet
              className="max-w-full py-2"
              color="danger"
              hideCopyButton
              hideSymbol
            >
              <MarkdownContainer>
                {attributes.check_metadata.risk}
              </MarkdownContainer>
            </Snippet>
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
            <h4 className="dark:text-prowler-theme-pale/90 text-sm font-bold text-gray-700">
              Remediation Details
            </h4>

            {/* Recommendation section */}
            {attributes.check_metadata.remediation.recommendation.text && (
              <InfoField label="Recommendation">
                <div className="flex flex-col gap-2">
                  <MarkdownContainer>
                    {attributes.check_metadata.remediation.recommendation.text}
                  </MarkdownContainer>

                  {attributes.check_metadata.remediation.recommendation.url && (
                    <CustomLink
                      href={
                        attributes.check_metadata.remediation.recommendation.url
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
                <Snippet className="bg-gray-50 py-1 dark:bg-slate-800">
                  <span className="text-xs whitespace-pre-line">
                    {attributes.check_metadata.remediation.code.cli}
                  </span>
                </Snippet>
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
          {attributes.check_metadata.categories?.join(", ") || "-"}
        </InfoField>
      </CustomSection>

      {/* Resource Details */}
      <CustomSection
        title={
          providerDetails.provider === "iac"
            ? (() => {
                // Extract line range from the Finding UID (may be null)
                const lineRange = extractLineRangeFromUid(attributes.uid);
                // Build URL with or without line range
                const gitUrl = buildGitFileUrl(
                  providerDetails.uid, // Repository URL
                  resource.name, // File path
                  lineRange || "", // Empty string if no line range
                );

                return (
                  <span className="flex items-center gap-2">
                    Resource Details
                    {gitUrl && (
                      <a
                        href={gitUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        title="Go to Resource in the Repository"
                        className="text-blue-600 transition-colors hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                        aria-label="Open resource in repository"
                      >
                        <ExternalLink size={16} />
                      </a>
                    )}
                  </span>
                );
              })()
            : "Resource Details"
        }
      >
        <InfoField label="Resource ID" variant="simple">
          <Snippet className="bg-gray-50 py-1 dark:bg-slate-800" hideSymbol>
            <span className="text-xs whitespace-pre-line">
              {renderValue(resource.uid)}
            </span>
          </Snippet>
        </InfoField>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Resource Name">
            {renderValue(resource.name)}
          </InfoField>
          <InfoField label="Resource Type">
            {renderValue(resource.type)}
          </InfoField>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Service">{renderValue(resource.service)}</InfoField>
          <InfoField label="Region">{renderValue(resource.region)}</InfoField>
        </div>

        {resource.tags && Object.entries(resource.tags).length > 0 && (
          <div className="flex flex-col gap-4">
            <h4 className="text-sm font-bold text-gray-500 dark:text-gray-400">
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
      </CustomSection>

      {/* Add new Scan Details section */}
      <CustomSection title="Scan Details">
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
      </CustomSection>
    </div>
  );
};
