"use client";

import { UseRadioProps } from "@nextui-org/radio/dist/use-radio";
import { cn, RadioGroup, useRadio, VisuallyHidden } from "@nextui-org/react";
import React from "react";
import { Control, Controller } from "react-hook-form";
import { z } from "zod";

import { addProviderFormSchema } from "@/types";

import { AWSProviderBadge, AzureProviderBadge } from "../icons/providers-badge";
import { GCPProviderBadge } from "../icons/providers-badge/GCPProviderBadge";
import { KS8ProviderBadge } from "../icons/providers-badge/KS8ProviderBadge";
import { FormMessage } from "../ui/form";

interface CustomRadioProps extends UseRadioProps {
  description?: string;
  children?: React.ReactNode;
}

export const CustomRadio: React.FC<CustomRadioProps> = (props) => {
  const {
    Component,
    children,
    description,
    getBaseProps,
    getWrapperProps,
    getInputProps,
    getLabelProps,
    getLabelWrapperProps,
    getControlProps,
  } = useRadio(props);

  return (
    <Component
      {...getBaseProps()}
      className={cn(
        "group inline-flex items-center hover:opacity-70 active:opacity-50 justify-between flex-row-reverse tap-highlight-transparent",
        "max-w-full cursor-pointer border-2 border-default rounded-lg gap-4 p-4",
        "data-[selected=true]:border-primary",
      )}
    >
      <VisuallyHidden>
        <input {...getInputProps()} />
      </VisuallyHidden>
      <span {...getWrapperProps()}>
        <span {...getControlProps()} />
      </span>
      <div {...getLabelWrapperProps()}>
        {children && <span {...getLabelProps()}>{children}</span>}
        {description && (
          <span className="text-small text-foreground opacity-70">
            {description}
          </span>
        )}
      </div>
    </Component>
  );
};

interface CustomRadioProviderProps {
  control: Control<z.infer<typeof addProviderFormSchema>>;
}

export const CustomRadioProvider: React.FC<CustomRadioProviderProps> = ({
  control,
}) => {
  return (
    <Controller
      name="providerType"
      control={control}
      render={({ field }) => (
        <>
          <RadioGroup label="Select one provider" {...field}>
            <CustomRadio description="Amazon Web Services" value="aws">
              <div className="flex items-center">
                <AWSProviderBadge size={26} />
                <span className="ml-2">AWS</span>
              </div>
            </CustomRadio>
            <CustomRadio description="Google Cloud Platform" value="gcp">
              <div className="flex items-center">
                <GCPProviderBadge size={26} />
                <span className="ml-2">GCP</span>
              </div>
            </CustomRadio>
            <CustomRadio description="Microsoft Azure" value="azure">
              <div className="flex items-center">
                <AzureProviderBadge size={26} />
                <span className="ml-2">Azure</span>
              </div>
            </CustomRadio>
            <CustomRadio description="Kubernetes" value="kubernetes">
              <div className="flex items-center">
                <KS8ProviderBadge size={26} />
                <span className="ml-2">Kubernetes</span>
              </div>
            </CustomRadio>
          </RadioGroup>
          <FormMessage className="text-system-error dark:text-system-error" />
        </>
      )}
    />
  );
};
