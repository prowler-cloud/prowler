"use client";

import { Select, SelectItem } from "@nextui-org/react";
import React from "react";
import { Control, Controller } from "react-hook-form";

import { ProviderProps, ProviderType } from "@/types/providers";

const providerTypeLabels: Record<ProviderType, string> = {
  aws: "Amazon Web Services",
  gcp: "Google Cloud Platform",
  azure: "Microsoft Azure",
  m365: "Microsoft 365",
  kubernetes: "Kubernetes",
};

interface ProviderSelectorProps {
  control: Control<any>;
  name: string;
  providers: ProviderProps[];
  label?: string;
  placeholder?: string;
  isRequired?: boolean;
  isInvalid?: boolean;
}

export const ProviderSelector: React.FC<ProviderSelectorProps> = ({
  control,
  name,
  providers,
  label = "Providers",
  placeholder = "Select providers",
  isRequired = false,
  isInvalid = false,
}) => {
  // Sort providers by type and then by name for better organization
  const sortedProviders = [...providers].sort((a, b) => {
    const typeComparison = a.attributes.provider.localeCompare(
      b.attributes.provider,
    );
    if (typeComparison !== 0) return typeComparison;

    const nameA = a.attributes.alias || a.attributes.uid;
    const nameB = b.attributes.alias || b.attributes.uid;
    return nameA.localeCompare(nameB);
  });

  return (
    <Controller
      control={control}
      name={name}
      render={({ field: { onChange, value, onBlur } }) => (
        <Select
          label={label}
          placeholder={placeholder}
          selectionMode="multiple"
          selectedKeys={new Set(value || [])}
          onSelectionChange={(keys) => {
            const selectedArray = Array.from(keys);
            onChange(selectedArray);
          }}
          onBlur={onBlur}
          variant="bordered"
          labelPlacement="inside"
          isRequired={isRequired}
          isInvalid={isInvalid}
          classNames={{
            trigger: "min-h-12",
            listboxWrapper: "max-h-[300px]",
            listbox: "gap-0",
          }}
          renderValue={(items) => {
            if (items.length === 0) {
              return <span className="text-default-500">{placeholder}</span>;
            }

            if (items.length === 1) {
              const provider = providers.find((p) => p.id === items[0].key);
              if (provider) {
                const displayName =
                  provider.attributes.alias || provider.attributes.uid;

                return (
                  <div className="flex items-center gap-2">
                    <span className="truncate">{displayName}</span>
                  </div>
                );
              }
            }

            return (
              <span className="text-small">
                {items.length} provider{items.length !== 1 ? "s" : ""} selected
              </span>
            );
          }}
        >
          {sortedProviders.map((provider) => {
            const providerType = provider.attributes.provider;
            const displayName =
              provider.attributes.alias || provider.attributes.uid;
            const typeLabel = providerTypeLabels[providerType];

            return (
              <SelectItem
                key={provider.id}
                textValue={`${displayName} ${typeLabel}`}
                className="py-2"
              >
                <div className="flex w-full items-center justify-between">
                  <div className="flex min-w-0 flex-1 items-center gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-small font-medium">
                        {displayName}
                      </div>
                      <div className="truncate text-tiny text-default-500">
                        {typeLabel}
                      </div>
                    </div>
                  </div>
                  <div className="ml-2 flex flex-shrink-0 items-center gap-2">
                    <div
                      className={`h-2 w-2 rounded-full ${
                        provider.attributes.connection.connected
                          ? "bg-success"
                          : "bg-danger"
                      }`}
                      title={
                        provider.attributes.connection.connected
                          ? "Connected"
                          : "Disconnected"
                      }
                    />
                  </div>
                </div>
              </SelectItem>
            );
          })}
        </Select>
      )}
    />
  );
};
