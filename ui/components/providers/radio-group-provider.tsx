"use client";

import { RadioGroup } from "@nextui-org/react";
import React from "react";
import { Control, Controller } from "react-hook-form";
import { z } from "zod";

import { addProviderFormSchema } from "@/types";

import { AWSProviderBadge, AzureProviderBadge } from "../icons/providers-badge";
import { GCPProviderBadge } from "../icons/providers-badge/GCPProviderBadge";
import { KS8ProviderBadge } from "../icons/providers-badge/KS8ProviderBadge";
import { CustomRadio } from "../ui/custom";
import { FormMessage } from "../ui/form";

interface RadioGroupProviderProps {
  control: Control<z.infer<typeof addProviderFormSchema>>;
  isInvalid: boolean;
  errorMessage?: string;
}

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
              <CustomRadio description="Amazon Web Services" value="aws">
                <div className="flex items-center">
                  <AWSProviderBadge size={26} />
                  <span className="ml-2">Amazon Web Services</span>
                </div>
              </CustomRadio>
              <CustomRadio description="Google Cloud Platform" value="gcp">
                <div className="flex items-center">
                  <GCPProviderBadge size={26} />
                  <span className="ml-2">Google Cloud Platform</span>
                </div>
              </CustomRadio>
              <CustomRadio description="Microsoft Azure" value="azure">
                <div className="flex items-center">
                  <AzureProviderBadge size={26} />
                  <span className="ml-2">Microsoft Azure</span>
                </div>
              </CustomRadio>
              <CustomRadio description="Kubernetes" value="kubernetes">
                <div className="flex items-center">
                  <KS8ProviderBadge size={26} />
                  <span className="ml-2">Kubernetes</span>
                </div>
              </CustomRadio>
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
