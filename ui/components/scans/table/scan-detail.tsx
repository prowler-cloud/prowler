"use client";

import { Card, CardBody, CardHeader, Divider } from "@nextui-org/react";

import { DateWithTime, SnippetId } from "@/components/ui/entities";
import { StatusBadge } from "@/components/ui/table/status-badge";
import { ScanProps, TaskDetails } from "@/types";

interface ScanDetailsProps {
  scanDetails: ScanProps & {
    taskDetails?: TaskDetails;
  };
}

export const ScanDetail = ({ scanDetails }: ScanDetailsProps) => {
  const scanOnDemand = scanDetails.attributes;
  const taskDetails = scanDetails.taskDetails;

  return (
    <div className="flex flex-col gap-6 rounded-lg">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-gray-800 dark:text-prowler-theme-pale/90">
          Scan Details
        </h2>
        <StatusBadge
          size="lg"
          status={scanOnDemand.state}
          loadingProgress={scanOnDemand.progress}
        />
      </div>

      <Divider className="border-gray-300 dark:border-gray-600" />

      {/* Details Section */}
      <div className="flex flex-col gap-4 rounded-lg p-4 shadow dark:bg-prowler-blue-400">
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
          <div className="flex flex-col gap-4">
            <DetailItem label="Scan Name" value={scanOnDemand.name} />
            <DetailItem
              label="ID"
              value={<SnippetId label="Type" entityId={scanDetails.id} />}
            />
            <DetailItem label="Trigger" value={scanOnDemand.trigger} />
            <DetailItem
              label="Resource Count"
              value={scanOnDemand.unique_resource_count.toString()}
            />
            <DetailItem label="Progress" value={`${scanOnDemand.progress}%`} />
            <DetailItem
              label="Duration"
              value={`${scanOnDemand.duration} seconds`}
            />
          </div>
          <div className="flex flex-col gap-4">
            <DateItem
              label="Started At"
              value={
                scanOnDemand.started_at ? (
                  <DateWithTime dateTime={scanOnDemand.started_at.toString()} />
                ) : (
                  "Not Started"
                )
              }
            />
            <DateItem
              label="Completed At"
              value={
                scanOnDemand.completed_at ? (
                  <DateWithTime
                    dateTime={scanOnDemand.completed_at.toString()}
                  />
                ) : (
                  "Not Completed"
                )
              }
            />
            <DateItem
              label="Scheduled At"
              value={
                scanOnDemand.scheduled_at ? (
                  <DateWithTime
                    dateTime={scanOnDemand.scheduled_at.toString()}
                  />
                ) : (
                  "Not Scheduled"
                )
              }
            />
            <DetailItem
              label="Provider ID"
              value={
                <SnippetId
                  label="Provider ID"
                  entityId={scanDetails.relationships.provider.data.id}
                />
              }
            />
            <DetailItem
              label="Task ID"
              value={
                scanDetails.relationships.task?.data?.id ? (
                  <SnippetId
                    label="Task ID"
                    entityId={scanDetails.relationships.task.data.id}
                  />
                ) : (
                  "N/A"
                )
              }
            />
          </div>
        </div>
      </div>

      {/* Scan Arguments Section */}
      {/* <Card className="rounded-lg p-4 shadow dark:bg-prowler-blue-400">
        <CardHeader className="pb-4">
          <h3 className="text-lg font-bold text-gray-800 dark:text-prowler-theme-pale/90">
            Scan Arguments
          </h3>
        </CardHeader>
        <Divider className="border-gray-300 dark:border-gray-600" />
        <CardBody className="pt-4">
          <div className="flex flex-col gap-2">
            <span className="text-sm font-semibold text-gray-600 dark:text-gray-300">
              Checks
            </span>
            <span className="text-gray-800 dark:text-prowler-theme-pale/90">
              {(scanOnDemand.scanner_args as any)?.checks_to_execute?.join(
                ", ",
              ) || "N/A"}
            </span>
          </div>
        </CardBody>
      </Card> */}

      {/* Task Details Section */}
      {taskDetails && (
        <Card className="rounded-lg p-4 shadow dark:bg-prowler-blue-400">
          <CardHeader className="pb-4">
            <h3 className="text-lg font-bold text-gray-800 dark:text-prowler-theme-pale/90">
              State Details
            </h3>
          </CardHeader>
          <Divider className="border-gray-300 dark:border-gray-600" />
          <CardBody className="pt-4">
            <div className="flex flex-col gap-4">
              <DetailItem label="State" value={taskDetails.attributes.state} />
              <DetailItem
                label="Completed At"
                value={taskDetails.attributes.completed_at || "N/A"}
              />
              {taskDetails.attributes.result && (
                <>
                  <DetailItem
                    label="Error Type"
                    value={taskDetails.attributes.result.exc_type || "N/A"}
                  />
                  {taskDetails.attributes.result.exc_message && (
                    <DetailItem
                      label="Error Message"
                      value={taskDetails.attributes.result.exc_message.join(
                        ", ",
                      )}
                    />
                  )}
                </>
              )}
              <DetailItem
                label="Checks to Execute"
                value={
                  taskDetails.attributes.task_args.checks_to_execute?.join(
                    ", ",
                  ) || "N/A"
                }
              />
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
};

const DateItem = ({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) => (
  <div className="flex items-center justify-between">
    <p className="text-sm font-semibold text-gray-600 dark:text-gray-300">
      {label}:
    </p>
    <p className="text-gray-800 dark:text-prowler-theme-pale/90">{value}</p>
  </div>
);

const DetailItem = ({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) => (
  <div className="flex items-center justify-between">
    <p className="text-sm font-semibold text-gray-600 dark:text-gray-300">
      {label}:
    </p>
    <p className="text-gray-800 dark:text-prowler-theme-pale/90">{value}</p>
  </div>
);
