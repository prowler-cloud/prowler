"use client";

import { Card, CardBody, CardHeader, Chip, Divider } from "@nextui-org/react";

import { ScanProps } from "@/types";

export const ScanDetail = ({ scanDetails }: { scanDetails: ScanProps }) => {
  return (
    <div className="space-y-4">
      <Card className="relative w-full border-small border-default-100 p-3 shadow-lg">
        <CardHeader className="flex items-center justify-between py-2">
          <h2 className="text-2xl font-bold">Scan Details</h2>
          <Chip
            color={
              scanDetails.attributes.state === "failed" ? "danger" : "success"
            }
            variant="faded"
          >
            {scanDetails.attributes.state}
          </Chip>
        </CardHeader>

        <Divider />

        <CardBody className="p-4">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="space-y-4">
              <DetailItem label="ID" value={scanDetails.id} />
              <DetailItem label="Name" value={scanDetails.attributes.name} />
              <DetailItem
                label="Trigger"
                value={scanDetails.attributes.trigger}
              />
              <DetailItem
                label="Resource Count"
                value={scanDetails.attributes.unique_resource_count.toString()}
              />
              <DetailItem
                label="Progress"
                value={`${scanDetails.attributes.progress}%`}
              />
              <DetailItem
                label="Duration"
                value={`${scanDetails.attributes.duration} seconds`}
              />
            </div>
            <div className="space-y-4">
              <DetailItem
                label="Started At"
                value={new Date(
                  scanDetails.attributes.started_at,
                ).toLocaleString()}
              />
              <DetailItem
                label="Completed At"
                value={new Date(
                  scanDetails.attributes.completed_at,
                ).toLocaleString()}
              />
              <DetailItem
                label="Scheduled At"
                value={
                  scanDetails.attributes.scheduled_at
                    ? new Date(
                        scanDetails.attributes.scheduled_at,
                      ).toLocaleString()
                    : "Not Scheduled"
                }
              />
              <DetailItem
                label="Provider ID"
                value={scanDetails.relationships.provider.data.id}
              />
              <DetailItem
                label="Task ID"
                value={scanDetails.relationships.task.data.id}
              />
            </div>
          </div>
        </CardBody>
      </Card>

      <Card className="relative w-full border-small border-default-100 p-3 shadow-lg">
        <CardHeader className="py-2">
          <h2 className="text-2xl font-bold">Scan Arguments</h2>
        </CardHeader>

        <Divider />

        <CardBody className="p-4">
          <DetailItem
            label="Checks"
            value={
              (
                scanDetails.attributes.scanner_args as any
              )?.checks_to_execute?.join(", ") || "N/A"
            }
          />
        </CardBody>
      </Card>
    </div>
  );
};

const DetailItem = ({ label, value }: { label: string; value: string }) => (
  <div className="flex items-center justify-between">
    <span className="font-semibold text-default-500">{label}:</span>
    <span className="text-default-700">{value}</span>
  </div>
);
