"use client";

import { Select, SelectItem } from "@nextui-org/react";
import { Control, FieldPath, FieldValues } from "react-hook-form";

import { AWSProviderBadge } from "@/components/icons/providers-badge/AWSProviderBadge";
import { AzureProviderBadge } from "@/components/icons/providers-badge/AzureProviderBadge";
import { GCPProviderBadge } from "@/components/icons/providers-badge/GCPProviderBadge";
import { KS8ProviderBadge } from "@/components/icons/providers-badge/KS8ProviderBadge";
import { FormControl, FormField, FormMessage } from "@/components/ui/form";

interface SelectScanProviderProps<
  TFieldValues extends FieldValues = FieldValues,
  TName extends FieldPath<TFieldValues> = FieldPath<TFieldValues>,
> {
  providers: {
    providerId: string;
    alias: string;
    providerType: string;
    uid: string;
    connected: boolean;
  }[];
  control: Control<TFieldValues>;
  name: TName;
}

export const SelectScanProvider = <
  TFieldValues extends FieldValues = FieldValues,
  TName extends FieldPath<TFieldValues> = FieldPath<TFieldValues>,
>({
  providers,
  control,
  name,
}: SelectScanProviderProps<TFieldValues, TName>) => {
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
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <>
          <FormControl>
            <Select
              aria-label="Select a scan job"
              placeholder="Choose a scan job"
              labelPlacement="outside"
              size="md"
              selectedKeys={field.value ? new Set([field.value]) : new Set()}
              onSelectionChange={(keys) => {
                const selectedValue = Array.from(keys)[0]?.toString();
                field.onChange(selectedValue);
              }}
              renderValue={() => {
                const selectedItem = providers.find(
                  (item) => item.providerId === field.value,
                );
                return selectedItem ? (
                  <div className="flex items-center gap-2">
                    {renderBadge(selectedItem.providerType)}
                    {selectedItem.alias}
                  </div>
                ) : (
                  "Choose a scan job"
                );
              }}
            >
              {providers.map((item) => (
                <SelectItem
                  key={item.providerId}
                  textValue={item.alias}
                  aria-label={item.alias}
                >
                  <div className="flex items-center gap-2">
                    {renderBadge(item.providerType)}
                    {item.alias}
                  </div>
                </SelectItem>
              ))}
            </Select>
          </FormControl>
          <FormMessage className="text-system-error dark:text-system-error" />
        </>
      )}
    />
  );
};
