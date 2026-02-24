"use client";

import { FC, useState } from "react";
import { Control, Controller } from "react-hook-form";
import { z } from "zod";

import { SearchInput } from "@/components/shadcn";
import { cn } from "@/lib/utils";
import { addProviderFormSchema } from "@/types";

import {
  AlibabaCloudProviderBadge,
  AWSProviderBadge,
  AzureProviderBadge,
  CloudflareProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  IacProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  MongoDBAtlasProviderBadge,
  OpenStackProviderBadge,
  OracleCloudProviderBadge,
} from "../icons/providers-badge";
import { FormMessage } from "../ui/form";

const PROVIDERS = [
  {
    value: "aws",
    label: "Amazon Web Services",
    badge: AWSProviderBadge,
  },
  {
    value: "gcp",
    label: "Google Cloud Platform",
    badge: GCPProviderBadge,
  },
  {
    value: "azure",
    label: "Microsoft Azure",
    badge: AzureProviderBadge,
  },
  {
    value: "m365",
    label: "Microsoft 365",
    badge: M365ProviderBadge,
  },
  {
    value: "mongodbatlas",
    label: "MongoDB Atlas",
    badge: MongoDBAtlasProviderBadge,
  },
  {
    value: "kubernetes",
    label: "Kubernetes",
    badge: KS8ProviderBadge,
  },
  {
    value: "github",
    label: "GitHub",
    badge: GitHubProviderBadge,
  },
  {
    value: "iac",
    label: "Infrastructure as Code",
    badge: IacProviderBadge,
  },
  {
    value: "oraclecloud",
    label: "Oracle Cloud Infrastructure",
    badge: OracleCloudProviderBadge,
  },
  {
    value: "alibabacloud",
    label: "Alibaba Cloud",
    badge: AlibabaCloudProviderBadge,
  },
  {
    value: "cloudflare",
    label: "Cloudflare",
    badge: CloudflareProviderBadge,
  },
  {
    value: "openstack",
    label: "OpenStack",
    badge: OpenStackProviderBadge,
  },
] as const;

interface RadioGroupProviderProps {
  control: Control<z.infer<typeof addProviderFormSchema>>;
  isInvalid: boolean;
  errorMessage?: string;
}

export const RadioGroupProvider: FC<RadioGroupProviderProps> = ({
  control,
  isInvalid,
  errorMessage,
}) => {
  const [searchTerm, setSearchTerm] = useState("");

  const lowerSearch = searchTerm.trim().toLowerCase();
  const filteredProviders = lowerSearch
    ? PROVIDERS.filter(
        (provider) =>
          provider.label.toLowerCase().includes(lowerSearch) ||
          provider.value.toLowerCase().includes(lowerSearch),
      )
    : PROVIDERS;

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
                  const BadgeComponent = provider.badge;
                  const isSelected = field.value === provider.value;

                  return (
                    <button
                      key={provider.value}
                      type="button"
                      role="option"
                      aria-selected={isSelected}
                      onClick={() => field.onChange(provider.value)}
                      className={cn(
                        "flex min-h-[72px] w-full items-center gap-4 rounded-lg border px-3 py-2.5 text-left transition-colors",
                        "focus-visible:border-primary focus-visible:outline-none",
                        isSelected
                          ? "border-primary bg-bg-neutral-tertiary"
                          : "border-border-neutral-primary bg-bg-neutral-tertiary hover:border-primary",
                        isInvalid && "border-bg-fail",
                      )}
                    >
                      <div className="border-border-neutral-primary bg-bg-input-primary flex size-[18px] shrink-0 items-center justify-center rounded-full border shadow-xs">
                        {isSelected && (
                          <div className="bg-primary size-2.5 rounded-full" />
                        )}
                      </div>

                      <div className="flex min-w-0 flex-1 items-center gap-1.5">
                        <BadgeComponent size={26} />
                        <span className="text-foreground text-sm leading-6">
                          {provider.label}
                        </span>
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
            <FormMessage className="text-text-error">
              {errorMessage}
            </FormMessage>
          )}
        </div>
      )}
    />
  );
};
