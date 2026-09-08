"use client";

import { FC, useState } from "react";
import { Control, Controller } from "react-hook-form";

import {
  ProviderTypeIcon,
  PROVIDER_TYPE_DATA,
} from "@/components/icons/providers-badge/provider-type-icon";
import { Badge, SearchInput } from "@/components/shadcn";
import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/shadcn/avatar";
import { FormMessage } from "@/components/shadcn/form";
import type { RegistryProviderOption } from "@/lib/registry/provider-options";
import { cn } from "@/lib/utils";
import type { AddProviderFormValues } from "@/types/formSchemas";

const PROVIDERS = Object.entries(PROVIDER_TYPE_DATA).map(
  ([value, { label }]) => ({ value, label }),
);

interface RadioGroupProviderProps {
  control: Control<AddProviderFormValues>;
  registryOptions?: RegistryProviderOption[];
  isInvalid: boolean;
  errorMessage?: string;
}

export const RadioGroupProvider: FC<RadioGroupProviderProps> = ({
  control,
  isInvalid,
  errorMessage,
  registryOptions = [],
}) => {
  const [searchTerm, setSearchTerm] = useState("");

  const options = [
    ...PROVIDERS.map((provider) => ({
      value: provider.value as string,
      label: provider.label as string,
      registry: false,
      logoUrl: undefined as string | undefined,
    })),
    ...registryOptions.map((provider) => ({
      value: provider.type,
      label: provider.label,
      registry: true,
      logoUrl: provider.logoUrl,
    })),
  ];
  const lowerSearch = searchTerm.trim().toLowerCase();
  const filteredProviders = lowerSearch
    ? options.filter(
        (provider) =>
          provider.label.toLowerCase().includes(lowerSearch) ||
          provider.value.toLowerCase().includes(lowerSearch),
      )
    : options;

  return (
    <Controller
      name="providerType"
      control={control}
      render={({ field }) => (
        <div className="flex flex-col px-4">
          <div className="relative z-10 shrink-0 pb-4">
            <SearchInput
              aria-label="Search providers"
              placeholder="Search providers..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onClear={() => setSearchTerm("")}
            />
          </div>

          <div className="relative">
            <div
              role="listbox"
              aria-label="Select a provider"
              className="flex flex-col gap-3"
            >
              {filteredProviders.length > 0 ? (
                filteredProviders.map((provider) => {
                  const isSelected = field.value === provider.value;

                  return (
                    <button
                      key={provider.value}
                      type="button"
                      role="option"
                      aria-label={`${provider.label}${provider.registry ? " Registry" : ""}`}
                      aria-selected={isSelected}
                      onClick={() => field.onChange(provider.value)}
                      className={cn(
                        "flex min-h-[72px] w-full items-center gap-4 rounded-lg border px-3 py-2.5 text-left transition-colors",
                        "focus-visible:border-button-primary focus-visible:outline-none",
                        isSelected
                          ? "border-button-primary bg-bg-neutral-tertiary"
                          : "border-border-neutral-primary bg-bg-neutral-tertiary hover:border-button-primary",
                        isInvalid && "border-bg-fail",
                      )}
                    >
                      <div className="border-border-neutral-primary bg-bg-input-primary flex size-[18px] shrink-0 items-center justify-center rounded-full border shadow-xs">
                        {isSelected && (
                          <div className="bg-button-primary size-2.5 rounded-full" />
                        )}
                      </div>

                      <div className="flex min-w-0 flex-1 items-center gap-1.5">
                        {provider.registry ? (
                          <Avatar>
                            <AvatarImage
                              src={
                                provider.logoUrl?.startsWith("https://")
                                  ? provider.logoUrl
                                  : undefined
                              }
                              alt=""
                            />
                            <AvatarFallback>
                              <ProviderTypeIcon
                                type={provider.value}
                                size={26}
                              />
                            </AvatarFallback>
                          </Avatar>
                        ) : (
                          <ProviderTypeIcon type={provider.value} size={26} />
                        )}
                        <span className="text-text-neutral-primary text-sm leading-6">
                          {provider.label}
                        </span>
                        {provider.registry && (
                          <Badge variant="tag">Registry</Badge>
                        )}
                      </div>
                    </button>
                  );
                })
              ) : (
                <p className="text-text-neutral-tertiary py-4 text-sm">
                  No providers found matching &quot;{searchTerm}&quot;
                </p>
              )}
            </div>
          </div>

          {errorMessage && (
            <FormMessage className="text-text-error-primary">
              {errorMessage}
            </FormMessage>
          )}
        </div>
      )}
    />
  );
};
