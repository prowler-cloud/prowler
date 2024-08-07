"use client";

import { UseRadioProps } from "@nextui-org/radio/dist/use-radio";
import { cn, RadioGroup, useRadio, VisuallyHidden } from "@nextui-org/react";
import React from "react";

import { AwsProvider, AzureProvider, GoogleCloudProvider } from "../icons";

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

export const CustomRadioProvider = () => {
  return (
    <RadioGroup label="Select one provider" name="provider">
      <CustomRadio description="Amazon Web Services" value="aws">
        <div className="flex items-center">
          <AwsProvider size={26} />
          <span className="ml-2">AWS</span>
        </div>
      </CustomRadio>
      <CustomRadio description="Google Cloud Platform" value="gcp">
        <div className="flex items-center">
          <GoogleCloudProvider size={26} />
          <span className="ml-2">GCP</span>
        </div>
      </CustomRadio>
      <CustomRadio description="Microsoft Azure" value="azure">
        <div className="flex items-center">
          <AzureProvider size={26} />
          <span className="ml-2">Azure</span>
        </div>
      </CustomRadio>
    </RadioGroup>
  );
};
