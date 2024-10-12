"use client";

import { Card, CardBody, CardHeader, Chip, Divider } from "@nextui-org/react";

import { ScanProps } from "@/types";

export const ScanDetail = ({ scanDetails }: { scanDetails: ScanProps }) => {
  return (
    <Card className="mx-auto max-w-xl">
      <CardHeader className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Scan Details</h2>
        <Chip
          color={
            scanDetails.attributes.state === "failed" ? "danger" : "success"
          }
        >
          {scanDetails.attributes.state}
        </Chip>
      </CardHeader>
      <Divider />
      <CardBody>
        <div className="space-y-4">
          <DetailItem label="ID" value={scanDetails.id} />
          <DetailItem label="Type" value={scanDetails.type} />
          <DetailItem label="Trigger" value={scanDetails.attributes.trigger} />
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
          <DetailItem
            label="Started At"
            value={new Date(scanDetails.attributes.started_at).toLocaleString()}
          />
          <DetailItem
            label="Completed At"
            value={new Date(
              scanDetails.attributes.completed_at,
            ).toLocaleString()}
          />
          <DetailItem
            label="Checks"
            value={
              scanDetails.attributes.scanner_args?.excluded_checks?.join(
                ", ",
              ) || ""
            }
          />
        </div>
      </CardBody>
    </Card>
  );
};

const DetailItem = ({ label, value }: { label: string; value: string }) => (
  <div className="flex justify-between">
    <span className="font-semibold">{label}:</span>
    <span>{value}</span>
  </div>
);
