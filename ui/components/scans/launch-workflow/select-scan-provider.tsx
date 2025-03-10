"use client";

import { Select, SelectItem } from "@nextui-org/react";
import { Control, FieldPath, FieldValues } from "react-hook-form";

import { EntityInfoShort } from "@/components/ui/entities";
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
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <>
          <FormControl>
            <Select
              aria-label="Select a cloud provider"
              placeholder="Choose a cloud provider"
              labelPlacement="outside"
              classNames={{
                selectorIcon: "right-2",
                label:
                  "tracking-tight font-light !text-default-500 text-xs !z-0",
                value: "text-default-500 text-xs",
              }}
              label="Select a cloud provider to launch a scan"
              size="lg"
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
                    <EntityInfoShort
                      cloudProvider={
                        selectedItem.providerType as
                          | "aws"
                          | "azure"
                          | "gcp"
                          | "kubernetes"
                      }
                      entityAlias={selectedItem.alias}
                      entityId={selectedItem.uid}
                      hideCopyButton
                    />
                  </div>
                ) : (
                  "Choose a cloud provider"
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
                    <EntityInfoShort
                      cloudProvider={
                        item.providerType as
                          | "aws"
                          | "azure"
                          | "gcp"
                          | "kubernetes"
                      }
                      entityAlias={item.alias}
                      entityId={item.uid}
                      hideCopyButton
                    />
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
