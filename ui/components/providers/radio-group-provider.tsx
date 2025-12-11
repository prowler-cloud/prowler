"use client";

import { Input } from "@heroui/input";
import { RadioGroup } from "@heroui/radio";
import { SearchIcon, XCircle } from "lucide-react";
import { FC, useState } from "react";
import { Control, Controller } from "react-hook-form";
import { z } from "zod";

import { addProviderFormSchema } from "@/types";

import {
  AlibabaCloudProviderBadge,
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  IacProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  MongoDBAtlasProviderBadge,
  OracleCloudProviderBadge,
} from "../icons/providers-badge";
import { CustomRadio } from "../ui/custom";
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
        <div className="flex flex-col gap-4">
          <Input
            aria-label="Search providers"
            placeholder="Search providers..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            startContent={
              <SearchIcon
                className="text-bg-button-secondary shrink-0"
                width={16}
              />
            }
            endContent={
              searchTerm && (
                <button
                  type="button"
                  aria-label="Clear search"
                  onClick={() => setSearchTerm("")}
                  className="text-bg-button-secondary shrink-0 focus:outline-none"
                >
                  <XCircle className="h-4 w-4" />
                </button>
              )
            }
            classNames={{
              base: "w-full",
              input:
                "text-bg-button-secondary placeholder:text-bg-button-secondary text-sm",
              inputWrapper:
                "!border-border-input-primary !bg-bg-input-primary dark:!bg-input/30 dark:hover:!bg-input/50 hover:!bg-bg-neutral-secondary !border !rounded-lg !shadow-xs !transition-[color,box-shadow] focus-within:!border-border-input-primary-press focus-within:!ring-1 focus-within:!ring-border-input-primary-press focus-within:!ring-offset-1 !h-10 !px-4 !py-3 !outline-none",
            }}
          />

          <RadioGroup
            className="flex flex-wrap"
            isInvalid={isInvalid}
            {...field}
            value={field.value || ""}
          >
            <div className="flex flex-col gap-4">
              {filteredProviders.length > 0 ? (
                filteredProviders.map((provider) => {
                  const BadgeComponent = provider.badge;
                  return (
                    <CustomRadio
                      key={provider.value}
                      description={provider.label}
                      value={provider.value}
                    >
                      <div className="flex items-center">
                        <BadgeComponent size={26} />
                        <span className="ml-2">{provider.label}</span>
                      </div>
                    </CustomRadio>
                  );
                })
              ) : (
                <p className="text-default-500 py-4 text-sm">
                  No providers found matching &quot;{searchTerm}&quot;
                </p>
              )}
            </div>
          </RadioGroup>

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
