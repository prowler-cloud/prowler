"use client";

import { Snippet } from "@nextui-org/react";

import {
  DateWithTime,
  EntityInfoShort,
  InfoField,
} from "@/components/ui/entities";
import { StatusBadge } from "@/components/ui/table/status-badge";
import { ProviderProps, ScanProps, TaskDetails } from "@/types";
import { ConnectionFalse } from "@/components/icons/Icons";
import { ConnectionTrue } from "@/components/icons";

const renderValue = (value: string | null | undefined) => {
  return value && value.trim() !== "" ? value : "-";
};

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

export const ScanDetail = ({
  scanDetails,
}: {
  scanDetails: ScanProps & {
    taskDetails?: TaskDetails;
    providerDetails?: ProviderProps;
  };
}) => {
  const scan = scanDetails.attributes;
  const taskDetails = scanDetails.taskDetails;
  const providerDetails = scanDetails.providerDetails?.attributes;

  return (
    <div className="flex flex-col gap-6 rounded-lg">
      {/* Header */}
      <div className="flex items-center justify-between">
        <StatusBadge
          size="lg"
          status={scan.state}
          loadingProgress={scan.progress}
        />
      </div>

      {/* Scan Details */}
      <Section title="Scan Details">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <InfoField label="Scan Name">{renderValue(scan.name)}</InfoField>
          <InfoField label="Resources Scanned">
            {scan.unique_resource_count}
          </InfoField>
          <InfoField label="Progress">{scan.progress}%</InfoField>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <InfoField label="Trigger">{renderValue(scan.trigger)}</InfoField>
          <InfoField label="State">{renderValue(scan.state)}</InfoField>
          <InfoField label="Duration">
            {formatDuration(scan.duration)}
          </InfoField>
        </div>

        {scan.state === "failed" && taskDetails?.attributes.result && (
          <>
            {taskDetails.attributes.result.exc_message && (
              <InfoField label="Error Message" variant="simple">
                <Snippet hideSymbol>
                  <span className="whitespace-pre-line text-xs">
                    {taskDetails.attributes.result.exc_message.join("\n")}
                  </span>
                </Snippet>
              </InfoField>
            )}
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <InfoField label="Error Type">
                {renderValue(taskDetails.attributes.result.exc_type)}
              </InfoField>
              <InfoField label="Scan ID" variant="simple">
                <Snippet hideSymbol>
                  {renderValue(taskDetails?.attributes.task_args.scan_id)}
                </Snippet>
              </InfoField>
            </div>
          </>
        )}

        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <InfoField label="Started At">
            <DateWithTime inline dateTime={scan.started_at || "-"} />
          </InfoField>
          <InfoField label="Completed At">
            <DateWithTime inline dateTime={scan.completed_at || "-"} />
          </InfoField>
          {scan.next_scan_at && (
            <InfoField label="Scheduled At">
              <DateWithTime inline dateTime={scan.next_scan_at} />
            </InfoField>
          )}
        </div>
      </Section>

      {/* Provider Details */}
      <Section title="Provider Details">
        {providerDetails ? (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <EntityInfoShort
              cloudProvider={
                providerDetails.provider as
                  | "aws"
                  | "azure"
                  | "gcp"
                  | "kubernetes"
              }
              entityAlias={providerDetails.alias}
              entityId={providerDetails.uid}
            />
            <InfoField label="Connection Status" variant="simple">
              {providerDetails.connection.connected ? (
                <ConnectionTrue className="text-system-success" size={24} />
              ) : (
                <ConnectionFalse className="text-danger" size={24} />
              )}
            </InfoField>
            <InfoField label="Last Checked">
              <DateWithTime
                inline
                dateTime={providerDetails.connection.last_checked_at}
              />
            </InfoField>
          </div>
        ) : (
          <span className="text-sm text-gray-500">
            No provider details available
          </span>
        )}
      </Section>
    </div>
  );
};
