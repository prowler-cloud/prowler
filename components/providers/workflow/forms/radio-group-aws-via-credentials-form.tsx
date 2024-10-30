"use client";

import { RadioGroup } from "@nextui-org/react";
import React from "react";
import { Control, Controller } from "react-hook-form";

import { CustomRadio } from "@/components/ui/custom";

import { FormValues } from "./connect-account-form";

type RadioGroupAWSViaCredentialsFormProps = {
  control: Control<FormValues>;
};

export const RadioGroupAWSViaCredentialsForm = ({
  control,
}: RadioGroupAWSViaCredentialsFormProps) => {
  return (
    <Controller
      name="awsCredentialsType"
      control={control}
      render={({ field }) => (
        <>
          <RadioGroup className="flex flex-wrap" {...field}>
            <div className="flex flex-col gap-4">
              <span className="text-sm text-default-500">Using IAM Role</span>
              <CustomRadio
                description="Connect via CloudFormation"
                value="cloudformation"
              >
                <div className="flex items-center">
                  <span className="ml-2">Connect via CloudFormation</span>
                </div>
              </CustomRadio>
              <CustomRadio
                description="Connect via Terraform"
                value="terraform"
              >
                <div className="flex items-center">
                  <span className="ml-2">Connect via Terraform</span>
                </div>
              </CustomRadio>
              <span className="text-sm text-default-500">
                Using Credentials
              </span>
              <CustomRadio
                description="Connect via Credentials"
                value="credentials"
              >
                <div className="flex items-center">
                  <span className="ml-2">Connect via Credentials</span>
                </div>
              </CustomRadio>
            </div>
          </RadioGroup>
        </>
      )}
    />
  );
};
