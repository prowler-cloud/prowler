"use client";

import { Snippet } from "@nextui-org/react";

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
          <h2 className="line-clamp-2 text-lg font-medium leading-tight text-gray-800 dark:text-prowler-theme-pale/90">
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
                  : "bg-red-100 text-system-severity-critical"
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
              <p className="whitespace-pre-line">
                {attributes.check_metadata.risk}
              </p>
            </Snippet>
          </InfoField>
        )}

        <InfoField label="Description">
          {renderValue(attributes.check_metadata.description)}
        </InfoField>

        <InfoField label="Status Extended">
          {renderValue(attributes.status_extended)}
        </InfoField>

        {attributes.check_metadata.remediation && (
          <div className="flex flex-col gap-4">
            <h4 className="text-sm font-bold text-gray-700 dark:text-prowler-theme-pale/90">
              Remediation Details
            </h4>

            {/* Recommendation section */}
            {attributes.check_metadata.remediation.recommendation.text && (
              <InfoField label="Recommendation">
                <div className="flex flex-col gap-2">
                  <p>
                    {attributes.check_metadata.remediation.recommendation.text}
                  </p>
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
                  <span className="whitespace-pre-line text-xs">
                    {attributes.check_metadata.remediation.code.cli}
                  </span>
                </Snippet>
              </InfoField>
            )}

            {/* Additional Resources section */}
            {attributes.check_metadata.remediation.code.other && (
              <InfoField label="Additional Resources">
                <CustomLink
                  href={attributes.check_metadata.remediation.code.other}
                  size="sm"
                >
                  View documentation
                </CustomLink>
              </InfoField>
            )}
          </div>
        )}

        <InfoField label="Categories">
          {attributes.check_metadata.categories?.join(", ") || "-"}
        </InfoField>
      </CustomSection>

      {/* Resource Details */}
      <CustomSection title="Resource Details">
        <InfoField label="Resource ID" variant="simple">
          <Snippet className="bg-gray-50 py-1 dark:bg-slate-800" hideSymbol>
            <span className="whitespace-pre-line text-xs">
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
