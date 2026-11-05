"use client";

import { FC, ReactNode, useState } from "react";
import { Control, Controller } from "react-hook-form";

import {
  ProviderTypeIcon,
  PROVIDER_TYPE_DATA,
} from "@/components/icons/providers-badge/provider-type-icon";
import { Badge, SearchInput } from "@/components/shadcn";
import { FormMessage } from "@/components/shadcn/form";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn/tabs/tabs";
import type { RegistryProviderOption } from "@/lib/registry/provider-options";
import { cn } from "@/lib/utils";
import type { AddProviderFormValues } from "@/types/formSchemas";

import { RegistryProviderLogo } from "./registry-provider-logo";

const PROVIDERS = Object.entries(PROVIDER_TYPE_DATA).map(
  ([value, { label }]) => ({ value, label }),
);

const PROVIDER_TAB = { ALL: "all", REGISTRY: "registry" } as const;
const REGISTRY_SKELETON_ROWS = 3;
// Tabs and search stay on top, opaque, while the providers scroll under them.
const STICKY_HEADER = "bg-bg-neutral-secondary sticky top-0 z-10 flex flex-col";
// Two providers per row beside a wide wizard, one while it stacks.
const PROVIDER_GRID = "grid gap-3 lg:grid-cols-2";
type ProviderTab = (typeof PROVIDER_TAB)[keyof typeof PROVIDER_TAB];

interface RadioGroupProviderProps {
  control: Control<AddProviderFormValues>;
  /**
   * Whether this deployment offers Registry providers (Cloud or Private Cloud
   * with the Registry flag on and a user allowed to manage providers). Off in
   * Local (OSS) and flag-off deployments, where the source tabs are hidden.
   */
  registryAvailable?: boolean;
  /** Discovery in flight: the Registry tab shows placeholder rows. */
  registryLoading?: boolean;
  /** Shown in the Registry tab instead of its list (upgrade, setup, retry). */
  registryNotice?: ReactNode;
  registryOptions?: RegistryProviderOption[];
  isInvalid: boolean;
  errorMessage?: string;
}

export const RadioGroupProvider: FC<RadioGroupProviderProps> = ({
  control,
  isInvalid,
  errorMessage,
  registryAvailable = false,
  registryLoading = false,
  registryNotice,
  registryOptions = [],
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedTab, setSelectedTab] = useState<ProviderTab>(PROVIDER_TAB.ALL);
  // Fall back to the full list if Registry access is revoked while the
  // Registry tab is selected, so the selector never shows an empty tab.
  const activeTab = registryAvailable ? selectedTab : PROVIDER_TAB.ALL;

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
  const tabProviders =
    activeTab === PROVIDER_TAB.REGISTRY
      ? options.filter((provider) => provider.registry)
      : options;
  const lowerSearch = searchTerm.trim().toLowerCase();
  const filteredProviders = lowerSearch
    ? tabProviders.filter(
        (provider) =>
          provider.label.toLowerCase().includes(lowerSearch) ||
          provider.value.toLowerCase().includes(lowerSearch),
      )
    : tabProviders;

  return (
    <Controller
      name="providerType"
      control={control}
      render={({ field }) => {
        const searchInput = (
          <div className="shrink-0 py-4">
            <SearchInput
              aria-label="Search providers"
              placeholder="Search providers..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onClear={() => setSearchTerm("")}
            />
          </div>
        );
        const providerList = (
          <div
            role="listbox"
            aria-label="Select a provider"
            className={PROVIDER_GRID}
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
                      // Focus scrolling clears the sticky header above the list.
                      registryAvailable ? "scroll-mt-32" : "scroll-mt-20",
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
                        <RegistryProviderLogo
                          type={provider.value}
                          logoUrl={provider.logoUrl}
                          size={26}
                        />
                      ) : (
                        <ProviderTypeIcon type={provider.value} size={26} />
                      )}
                      <span className="text-text-neutral-primary min-w-0 truncate text-sm leading-6">
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
              <p className="text-text-neutral-tertiary col-span-full py-4 text-sm">
                {lowerSearch ? (
                  <>No providers found matching &quot;{searchTerm}&quot;</>
                ) : (
                  "No Registry providers available."
                )}
              </p>
            )}
          </div>
        );
        const registryPlaceholder = registryLoading ? (
          <div
            role="status"
            aria-label="Loading Registry providers"
            className={PROVIDER_GRID}
          >
            {Array.from({ length: REGISTRY_SKELETON_ROWS }, (_, index) => (
              <Skeleton key={index} className="h-[72px] w-full rounded-lg" />
            ))}
          </div>
        ) : (
          registryNotice
        );
        const validationMessage = errorMessage && (
          <FormMessage className="text-text-error-primary">
            {errorMessage}
          </FormMessage>
        );

        if (!registryAvailable) {
          return (
            <div className="flex flex-col px-4">
              <div data-slot="provider-picker-header" className={STICKY_HEADER}>
                {searchInput}
              </div>
              <div className="mt-2">{providerList}</div>
              {validationMessage}
            </div>
          );
        }

        return (
          <Tabs
            className="flex flex-col px-4"
            value={activeTab}
            onValueChange={(value) => setSelectedTab(value as ProviderTab)}
          >
            <div data-slot="provider-picker-header" className={STICKY_HEADER}>
              <TabsList aria-label="Provider source">
                <TabsTrigger value={PROVIDER_TAB.ALL}>
                  All providers
                </TabsTrigger>
                <TabsTrigger value={PROVIDER_TAB.REGISTRY}>
                  Registry
                </TabsTrigger>
              </TabsList>
              {searchInput}
            </div>
            <TabsContent value={activeTab}>
              {activeTab === PROVIDER_TAB.REGISTRY && registryPlaceholder
                ? registryPlaceholder
                : providerList}
            </TabsContent>
            {validationMessage}
          </Tabs>
        );
      }}
    />
  );
};
