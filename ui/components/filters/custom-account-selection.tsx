"use client";
import { Select, SelectItem } from "@nextui-org/react";

const accounts = [
  { key: "audit-test-1", label: "740350143844" },
  { key: "audit-test-2", label: "890837126756" },
  { key: "audit-test-3", label: "563829104923" },
  { key: "audit-test-4", label: "678943217543" },
  { key: "audit-test-5", label: "932187465320" },
  { key: "audit-test-6", label: "492837106587" },
  { key: "audit-test-7", label: "812736459201" },
  { key: "audit-test-8", label: "374829106524" },
  { key: "audit-test-9", label: "926481053298" },
  { key: "audit-test-10", label: "748192364579" },
  { key: "audit-test-11", label: "501374829106" },
];
export const CustomAccountSelection = () => {
  return (
    <Select
      label="Account"
      aria-label="Select an Account"
      placeholder="Select an account"
      selectionMode="multiple"
      className="w-full"
      size="sm"
    >
      {accounts.map((acc) => (
        <SelectItem key={acc.key}>{acc.label}</SelectItem>
      ))}
    </Select>
  );
};
