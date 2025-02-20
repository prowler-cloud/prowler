"use client";

import { Snippet } from "@nextui-org/react";
import Link from "next/link";

import { InfoField } from "@/components/ui/entities";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import {
  getProviderLogo,
  type ProviderType,
} from "@/components/ui/entities/get-provider-logo";
import { SeverityBadge } from "@/components/ui/table/severity-badge";
import { FindingProps } from "@/types";

const renderValue = (value: string | null | undefined) => {
  return value && value.trim() !== "" ? value : "-";
};

const Section = ({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) => (
  <div className="flex flex-col gap-4 rounded-lg p-4 shadow dark:bg-prowler-blue-400">
    <h3 className="text-md font-medium text-gray-800 dark:text-prowler-theme-pale/90">
      {title}
    </h3>
    {children}
  </div>
);

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
  const provider = finding.relationships.provider.attributes;

  return (
    <div className="flex flex-col gap-6 rounded-lg">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="line-clamp-2 text-lg font-medium leading-tight text-gray-800 dark:text-prowler-theme-pale/90">
            {renderValue(attributes.check_metadata.checktitle)}
          </h2>
        </div>

        <div
          className={`rounded-lg px-3 py-1 text-sm font-semibold ${
            attributes.status === "PASS"
              ? "bg-green-100 text-green-600"
              : attributes.status === "MANUAL"
                ? "bg-gray-100 text-gray-600"
                : "bg-red-100 text-red-600"
          }`}
        >
          {renderValue(attributes.status)}
        </div>
      </div>

      {/* Check Metadata */}
      <Section title="Finding Details">
        <div className="mb-4 grid grid-cols-1 gap-4 md:grid-cols-4">
          <InfoField label="Provider" variant="simple">
            <div className="flex items-center gap-2">
              {getProviderLogo(
                attributes.check_metadata.provider as ProviderType,
              )}
            </div>
          </InfoField>
          <InfoField label="Service">
            {attributes.check_metadata.servicename}
          </InfoField>
          <InfoField label="Region">{resource.region}</InfoField>
          <InfoField label="First Seen">
            <DateWithTime inline dateTime={attributes.first_seen_at || "-"} />
          </InfoField>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Check ID" variant="simple">
            <Snippet
              className="max-w-full bg-gray-50 py-1 text-xs dark:bg-slate-800"
              hideSymbol
            >
              {attributes.check_id}
            </Snippet>
          </InfoField>
          <InfoField label="Severity" variant="simple">
            <SeverityBadge severity={attributes.severity || "-"} />
          </InfoField>
        </div>

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
                    <Link
                      href={
                        attributes.check_metadata.remediation.recommendation.url
                      }
                      target="_blank"
                      className="text-sm text-blue-500 hover:underline"
                    >
                      Learn more
                    </Link>
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
                <Link
                  href={attributes.check_metadata.remediation.code.other}
                  target="_blank"
                  className="text-sm text-blue-500 hover:underline"
                >
                  View documentation
                </Link>
              </InfoField>
            )}
          </div>
        )}

        <InfoField label="Categories">
          {attributes.check_metadata.categories?.join(", ") || "-"}
        </InfoField>
      </Section>

      {/* Resource Details */}
      <Section title="Resource Details">
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
            {Object.entries(resource.tags).map(([key, value]) => (
              <InfoField key={key} label={key}>
                {renderValue(value)}
              </InfoField>
            ))}
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
      </Section>

      {/* Add new Scan Details section */}
      <Section title="Scan Details">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <InfoField label="Scan Name">{scan.name}</InfoField>
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
          <InfoField label="Next Scan">
            <DateWithTime inline dateTime={scan.next_scan_at || "-"} />
          </InfoField>
        </div>

        {scan.scheduled_at && (
          <InfoField label="Scheduled At">
            <DateWithTime inline dateTime={scan.scheduled_at} />
          </InfoField>
        )}
      </Section>

      {/* Provider Details section */}
      <Section title="Provider Details">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Provider" variant="simple">
            {getProviderLogo(
              attributes.check_metadata.provider as ProviderType,
            )}
          </InfoField>
          <InfoField label="Account ID">{provider.uid}</InfoField>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Alias">{provider.alias}</InfoField>
          <InfoField label="Connection Status">
            <span
              className={`${provider.connection.connected ? "text-green-500" : "text-red-500"}`}
            >
              {provider.connection.connected ? "Connected" : "Disconnected"}
            </span>
          </InfoField>
        </div>
      </Section>
    </div>
  );
};
