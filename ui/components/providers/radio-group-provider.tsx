"use client";

import { RadioGroup } from "@nextui-org/react";
import React from "react";
import { Control, Controller } from "react-hook-form";
import { z } from "zod";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
} from "@/components/icons/providers-badge";
import { CustomRadio } from "@/components/ui/custom";
import { FormMessage } from "@/components/ui/form";
import { addProviderFormSchema, IconSvgProps } from "@/types";

interface RadioGroupProviderProps {
  control: Control<z.infer<typeof addProviderFormSchema>>;
  isInvalid: boolean;
  errorMessage?: string;
}

const PROVIDERS_CONFIG = [
  {
    value: "aws",
    name: "Amazon Web Services",
    description: "Amazon Web Services",
    BadgeComponent: AWSProviderBadge,
  },
  {
    value: "gcp",
    name: "Google Cloud Platform",
    description: "Google Cloud Platform",
    BadgeComponent: GCPProviderBadge,
  },
  {
    value: "azure",
    name: "Microsoft Azure",
    description: "Microsoft Azure",
    BadgeComponent: AzureProviderBadge,
  },
  {
    value: "m365",
    name: "Microsoft 365",
    description: "Microsoft 365",
    BadgeComponent: M365ProviderBadge,
  },
  {
    value: "kubernetes",
    name: "Kubernetes",
    description: "Kubernetes",
    BadgeComponent: KS8ProviderBadge,
  },
  {
    value: "github",
    name: "GitHub",
    description: "GitHub",
    BadgeComponent: GitHubProviderBadge,
  },
] as const;

const ProviderRadio = ({
  value,
  name,
  description,
  BadgeComponent,
}: {
  value: string;
  name: string;
  description: string;
  BadgeComponent: React.FC<IconSvgProps>;
}) => (
  <CustomRadio description={description} value={value}>
    <div className="flex items-center">
      <BadgeComponent size={26} />
      <span className="ml-2">{name}</span>
    </div>
  </CustomRadio>
);

export const RadioGroupProvider: React.FC<RadioGroupProviderProps> = ({
  control,
  isInvalid,
  errorMessage,
}) => {
  return (
    <Controller
      name="providerType"
      control={control}
      render={({ field }) => (
        <>
          <RadioGroup
            className="flex flex-wrap"
            isInvalid={isInvalid}
            {...field}
            value={field.value || ""}
          >
            <div className="flex flex-col gap-4">
              {PROVIDERS_CONFIG.map((provider) => (
                <ProviderRadio
                  key={provider.value}
                  value={provider.value}
                  name={provider.name}
                  description={provider.description}
                  BadgeComponent={provider.BadgeComponent}
                />
              ))}
            </div>
          </RadioGroup>
          {errorMessage && (
            <FormMessage className="text-system-error dark:text-system-error">
              {errorMessage}
            </FormMessage>
          )}
        </>
      )}
    />
  );
};
