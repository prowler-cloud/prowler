"use client";

import { Control, FieldPath, FieldValues } from "react-hook-form";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
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
      render={({ field }) => {
        const selectedItem = providers.find(
          (item) => item.providerId === field.value,
        );

        return (
          <div className="flex flex-col gap-2">
            <span className="text-text-neutral-primary text-sm font-medium">
              Select a cloud provider to launch a scan
            </span>
            <FormControl>
              <Select
                value={field.value}
                onValueChange={field.onChange}
                ariaLabel="Select a cloud provider"
              >
                <SelectTrigger>
                  <SelectValue placeholder="Choose a cloud provider">
                    {selectedItem ? (
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
                    ) : (
                      "Choose a cloud provider"
                    )}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {providers.map((item) => (
                    <SelectItem key={item.providerId} value={item.providerId}>
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
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FormControl>
            <FormMessage className="text-sm text-red-600 dark:text-red-400" />
          </div>
        );
      }}
    />
  );
};
