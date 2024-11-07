"use client";

import { Select, SelectItem } from "@nextui-org/react";
import { useState } from "react";

import { AWSProviderBadge } from "@/components/icons/providers-badge/AWSProviderBadge";
import { AzureProviderBadge } from "@/components/icons/providers-badge/AzureProviderBadge";
import { GCPProviderBadge } from "@/components/icons/providers-badge/GCPProviderBadge";
import { KS8ProviderBadge } from "@/components/icons/providers-badge/KS8ProviderBadge";

interface SelectScanProviderProps {
  providers: {
    alias: string;
    providerType: string;
    uid: string;
    connected: boolean;
  }[];
}

export const SelectScanProvider = ({ providers }: SelectScanProviderProps) => {
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set());

  const renderBadge = (providerType: string) => {
    switch (providerType) {
      case "aws":
        return <AWSProviderBadge width={25} height={25} />;
      case "azure":
        return <AzureProviderBadge width={25} height={25} />;
      case "gcp":
        return <GCPProviderBadge width={25} height={25} />;
      case "kubernetes":
        return <KS8ProviderBadge width={25} height={25} />;
      default:
        return null;
    }
  };

  return (
    <Select
      aria-label="Select a Provider"
      placeholder="Choose a provider"
      labelPlacement="outside"
      size="sm"
      selectedKeys={selectedKeys}
      onSelectionChange={(keys) => setSelectedKeys(new Set(keys))}
      renderValue={() => {
        const selectedItem = providers.find(
          (item) => item.uid === Array.from(selectedKeys)[0],
        );
        return selectedItem ? (
          <div className="flex items-center gap-2">
            {renderBadge(selectedItem.providerType)}
            {selectedItem.alias}
          </div>
        ) : (
          "Choose a provider"
        );
      }}
    >
      {providers.map((item) => (
        <SelectItem key={item.uid} textValue={item.uid} aria-label={item.alias}>
          <div className="flex items-center gap-2">
            {renderBadge(item.providerType)}
            {item.alias}
          </div>
        </SelectItem>
      ))}
    </Select>
  );
};
