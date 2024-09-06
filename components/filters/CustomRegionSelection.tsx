"use client";
import { Select, SelectItem } from "@nextui-org/react";

const regions = [
  { key: "af-south-1", label: "AF South 1" },
  { key: "ap-east-1", label: "AP East 1" },
  { key: "ap-northeast-1", label: "AP Northeast 1" },
  { key: "ap-northeast-2", label: "AP Northeast 2" },
  { key: "ap-northeast-3", label: "AP Northeast 3" },
  { key: "ap-south-1", label: "AP South 1" },
  { key: "ap-south-2", label: "AP South 2" },
  { key: "ap-southeast-1", label: "AP Southeast 1" },
  { key: "ap-southeast-2", label: "AP Southeast 2" },
  { key: "ap-southeast-3", label: "AP Southeast 3" },
  { key: "ap-southeast-4", label: "AP Southeast 4" },
  { key: "ca-central-1", label: "CA Central 1" },
  { key: "ca-west-1", label: "CA West 1" },
  { key: "eu-central-1", label: "EU Central 1" },
  { key: "eu-central-2", label: "EU Central 2" },
  { key: "eu-north-1", label: "EU North 1" },
  { key: "eu-south-1", label: "EU South 1" },
  { key: "eu-south-2", label: "EU South 2" },
  { key: "eu-west-1", label: "EU West 1" },
  { key: "eu-west-2", label: "EU West 2" },
  { key: "eu-west-3", label: "EU West 3" },
  { key: "il-central-1", label: "IL Central 1" },
  { key: "me-central-1", label: "ME Central 1" },
  { key: "me-south-1", label: "ME South 1" },
  { key: "sa-east-1", label: "SA East 1" },
  { key: "us-east-1", label: "US East 1" },
  { key: "us-east-2", label: "US East 2" },
  { key: "us-west-1", label: "US West 1" },
  { key: "us-west-2", label: "US West 2" },
];

export const CustomRegionSelection = () => {
  return (
    <Select
      label="Region"
      placeholder="Select a region"
      selectionMode="multiple"
      className="w-full"
      size="sm"
    >
      {regions.map((acc) => (
        <SelectItem key={acc.key}>{acc.label}</SelectItem>
      ))}
    </Select>
  );
};
