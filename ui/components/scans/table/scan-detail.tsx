"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { DateWithTime, EntityInfo, InfoField } from "@/components/ui/entities";
import { StatusBadge } from "@/components/ui/table/status-badge";
import { formatDuration } from "@/lib/date-utils";
import { ProviderProps, ProviderType, ScanProps, TaskDetails } from "@/types";

const renderValue = (value: string | null | undefined) => {
  return value && value.trim() !== "" ? value : "-";
};

export const ScanDetail = ({
  scanDetails,
}: {
  scanDetails: ScanProps & {
    taskDetails?: TaskDetails;
    // TODO: Remove the "?" once we have a proper provider details type
    providerDetails?: ProviderProps;
  };
}) => {
  const scan = scanDetails.attributes;
  const taskDetails = scanDetails.taskDetails;
  const providerDetails = scanDetails.providerDetails?.attributes;

  return (
    <div className="flex flex-col gap-6 rounded-lg">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="flex items-center">
          <StatusBadge
            size="md"
            className="w-fit"
            status={scan.state}
            loadingProgress={scan.progress}
          />
        </div>
        <EntityInfo
          cloudProvider={providerDetails?.provider as ProviderType}
          entityAlias={providerDetails?.alias}
          entityId={providerDetails?.uid}
          showConnectionStatus={providerDetails?.connection.connected}
        />
      </div>

      {/* Scan Details */}
      <Card variant="base" padding="lg">
        <CardHeader>
          <CardTitle>Scan Details</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
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

          <InfoField label="Scan ID" variant="simple">
            <CodeSnippet value={scanDetails.id} />
          </InfoField>

          {scan.state === "failed" && taskDetails?.attributes.result && (
            <>
              {taskDetails.attributes.result.exc_message && (
                <InfoField label="Error Message" variant="simple">
                  <CodeSnippet
                    value={taskDetails.attributes.result.exc_message.join("\n")}
                    multiline
                  />
                </InfoField>
              )}
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <InfoField label="Error Type">
                  {renderValue(taskDetails.attributes.result.exc_type)}
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
            <InfoField label="Scheduled At">
              <DateWithTime inline dateTime={scan.scheduled_at || "-"} />
            </InfoField>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
