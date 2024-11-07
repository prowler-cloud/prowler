"use client";

import { Card, CardBody, CardHeader, Divider } from "@nextui-org/react";

import { DateWithTime, SnippetId } from "@/components/ui/entities";
import { StatusBadge } from "@/components/ui/table/status-badge";
import { ScanProps } from "@/types";

export const ScanDetail = ({ scanDetails }: { scanDetails: ScanProps }) => {
  const scanOnDemand = scanDetails.attributes;
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex flex-col items-baseline md:flex-row md:gap-x-4">
          <h2 className="text-lg font-black uppercase">Scan Details - </h2>
          <p>{scanOnDemand.name}</p>
        </div>

        <StatusBadge size="lg" status={scanOnDemand.state} />
      </div>
      <Divider />
      <div className="relative z-0 flex w-full flex-col justify-between gap-4 overflow-auto rounded-large bg-content1 p-4 shadow-small">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="space-y-4">
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
          <div className="space-y-4">
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
                  "Not Started"
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
      <Card className="relative w-full border-small border-default-100 p-3 shadow-lg">
        <CardHeader className="py-2">
          <h2 className="text-2xl font-bold">Scan Arguments</h2>
        </CardHeader>

        <Divider />

        <CardBody className="p-4">
          <div className="flex flex-col gap-2">
            <span className="font-semibold text-default-500">Checks</span>
            <span className="text-default-700">
              {(scanOnDemand.scanner_args as any)?.checks_to_execute?.join(
                ", ",
              ) || "N/A"}
            </span>
          </div>
        </CardBody>
      </Card>
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
    <span className="font-semibold text-default-500">{label}:</span>
    <span className="text-default-700">{value}</span>
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
    <span className="font-semibold text-default-500">{label}:</span>
    <span className="text-default-700">{value}</span>
  </div>
);
