"use client";

import { Input } from "@heroui/input";
import { Select, SelectItem } from "@heroui/select";
import { SharedSelection } from "@heroui/system";
import { CheckSquare, Search, Square } from "lucide-react";
import { useState } from "react";
import { Control, FieldValues, Path } from "react-hook-form";

import { Button } from "@/components/shadcn";
import { FormControl, FormField, FormMessage } from "@/components/ui/form";
import { ProviderProps, ProviderType } from "@/types/providers";

const providerTypeLabels: Record<ProviderType, string> = {
  aws: "Amazon Web Services",
  gcp: "Google Cloud Platform",
  azure: "Microsoft Azure",
  m365: "Microsoft 365",
  kubernetes: "Kubernetes",
  github: "GitHub",
  iac: "Infrastructure as Code",
  oraclecloud: "Oracle Cloud Infrastructure",
  mongodbatlas: "MongoDB Atlas",
  alibabacloud: "Alibaba Cloud",
};

interface EnhancedProviderSelectorProps<T extends FieldValues> {
  control: Control<T>;
  name: Path<T>;
  providers: ProviderProps[];
  label?: string;
  placeholder?: string;
  isInvalid?: boolean;
  showFormMessage?: boolean;
  selectionMode?: "single" | "multiple";
  providerType?: ProviderType;
  enableSearch?: boolean;
  disabledProviderIds?: string[];
}

export const EnhancedProviderSelector = <T extends FieldValues>({
  control,
  name,
  providers,
  label = "Provider",
  placeholder = "Select provider",
  isInvalid = false,
  showFormMessage = true,
  selectionMode = "single",
  providerType,
  enableSearch = false,
  disabledProviderIds = [],
}: EnhancedProviderSelectorProps<T>) => {
  const [searchValue, setSearchValue] = useState("");

  const filteredProviders = (() => {
    let filtered = providers;

    // Filter by provider type if specified
    if (providerType) {
      filtered = filtered.filter((p) => p.attributes.provider === providerType);
    }

    // Filter by search value
    if (searchValue && enableSearch) {
      const lowerSearch = searchValue.toLowerCase();
      filtered = filtered.filter((p) => {
        const displayName = p.attributes.alias || p.attributes.uid;
        const typeLabel = providerTypeLabels[p.attributes.provider];
        return (
          displayName.toLowerCase().includes(lowerSearch) ||
          typeLabel.toLowerCase().includes(lowerSearch)
        );
      });
    }

    // Sort providers
    return filtered.sort((a, b) => {
      const typeComparison = a.attributes.provider.localeCompare(
        b.attributes.provider,
      );
      if (typeComparison !== 0) return typeComparison;

      const nameA = a.attributes.alias || a.attributes.uid;
      const nameB = b.attributes.alias || b.attributes.uid;
      return nameA.localeCompare(nameB);
    });
  })();

  return (
    <FormField
      control={control}
      name={name}
      render={({ field: { onChange, value, onBlur } }) => {
        const isMultiple = selectionMode === "multiple";
        const selectedIds: string[] = isMultiple
          ? (value as string[] | undefined) || []
          : value
            ? [value as string]
            : [];
        const allProviderIds = filteredProviders
          .filter((p) => !disabledProviderIds.includes(p.id))
          .map((p) => p.id);
        const isAllSelected =
          isMultiple &&
          allProviderIds.length > 0 &&
          allProviderIds.every((id) => selectedIds.includes(id));

        const handleSelectAll = () => {
          if (isAllSelected) {
            onChange([]);
          } else {
            onChange(allProviderIds);
          }
        };

        const handleSelectionChange = (keys: SharedSelection) => {
          if (keys === "all") {
            onChange(allProviderIds);
            return;
          }
          if (isMultiple) {
            const selectedArray = Array.from(keys).map(String);
            onChange(selectedArray);
          } else {
            const selectedValue = Array.from(keys)[0];
            onChange(selectedValue ? String(selectedValue) : "");
          }
        };

        return (
          <>
            <FormControl>
              <div className="flex flex-col gap-2">
                {isMultiple && filteredProviders.length > 1 && (
                  <div className="flex items-center justify-between">
                    <span className="text-text-neutral-primary text-sm font-medium">
                      {label}
                    </span>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={handleSelectAll}
                      className="h-7 text-xs"
                    >
                      {isAllSelected ? (
                        <CheckSquare size={16} />
                      ) : (
                        <Square size={16} />
                      )}
                      {isAllSelected ? "Deselect All" : "Select All"}
                    </Button>
                  </div>
                )}
                <Select
                  label={label}
                  placeholder={placeholder}
                  selectionMode={isMultiple ? "multiple" : "single"}
                  selectedKeys={
                    new Set(isMultiple ? value || [] : value ? [value] : [])
                  }
                  onSelectionChange={handleSelectionChange}
                  onBlur={onBlur}
                  variant="bordered"
                  labelPlacement="inside"
                  isRequired={false}
                  isInvalid={isInvalid}
                  classNames={{
                    trigger: "min-h-12",
                    popoverContent: "bg-bg-neutral-secondary",
                    listboxWrapper: "max-h-[300px] bg-bg-neutral-secondary",
                    listbox: "gap-0",
                    label:
                      "tracking-tight font-light !text-text-neutral-secondary text-xs z-0!",
                    value: "text-text-neutral-secondary text-small",
                  }}
                  renderValue={(items) => {
                    if (!isMultiple && value) {
                      const provider = providers.find((p) => p.id === value);
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

                    if (items.length === 0) {
                      return (
                        <span className="text-default-500">{placeholder}</span>
                      );
                    }

                    if (isMultiple) {
                      if (items.length === 1) {
                        const provider = providers.find(
                          (p) => p.id === items[0].key,
                        );
                        if (provider) {
                          const displayName =
                            provider.attributes.alias ||
                            provider.attributes.uid;
                          return (
                            <div className="flex items-center gap-2">
                              <span className="truncate">{displayName}</span>
                            </div>
                          );
                        }
                      }

                      return (
                        <span className="text-small">
                          {items.length} provider{items.length !== 1 ? "s" : ""}{" "}
                          selected
                        </span>
                      );
                    }

                    return null;
                  }}
                  listboxProps={{
                    topContent: enableSearch ? (
                      <div className="sticky top-0 z-10 py-2">
                        <Input
                          isClearable
                          placeholder="Search providers..."
                          size="sm"
                          variant="bordered"
                          startContent={<Search size={16} />}
                          value={searchValue}
                          onValueChange={setSearchValue}
                          onClear={() => setSearchValue("")}
                          classNames={{
                            inputWrapper:
                              "border-border-input-primary bg-bg-input-primary hover:bg-bg-neutral-secondary",
                            input: "text-small",
                            clearButton: "text-default-400",
                          }}
                        />
                      </div>
                    ) : null,
                  }}
                >
                  {filteredProviders.map((provider) => {
                    const providerType = provider.attributes.provider;
                    const displayName =
                      provider.attributes.alias || provider.attributes.uid;
                    const typeLabel = providerTypeLabels[providerType];
                    const isDisabled = disabledProviderIds.includes(
                      provider.id,
                    );

                    return (
                      <SelectItem
                        key={provider.id}
                        textValue={`${displayName} ${typeLabel}`}
                        className={`py-2 ${isDisabled ? "pointer-events-none cursor-not-allowed opacity-50" : ""}`}
                      >
                        <div className="flex w-full items-center justify-between">
                          <div className="flex min-w-0 flex-1 items-center gap-3">
                            <div className="min-w-0 flex-1">
                              <div className="text-small truncate font-medium">
                                {displayName}
                              </div>
                              <div className="text-tiny text-text-neutral-secondary truncate">
                                {typeLabel}
                                {isDisabled && (
                                  <span className="text-text-error ml-2">
                                    (Already used)
                                  </span>
                                )}
                              </div>
                            </div>
                          </div>
                          <div className="ml-2 flex shrink-0 items-center gap-2">
                            <div
                              className={`h-2 w-2 rounded-full ${
                                provider.attributes.connection.connected
                                  ? "bg-bg-pass"
                                  : "bg-bg-fail"
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
              </div>
            </FormControl>
            {showFormMessage && (
              <FormMessage className="text-text-error max-w-full text-xs" />
            )}
          </>
        );
      }}
    />
  );
};
