"use client";

import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { Form } from "@/components/shadcn/form";

import {
  AzureCredentialsTypeFormValues,
  RadioGroupAzureViaCredentialsTypeForm,
} from "./radio-group-azure-via-credentials-type-form";

interface SelectViaAzureProps {
  initialVia?: string;
  onViaChange?: (via: string) => void;
}

export const SelectViaAzure = ({
  initialVia,
  onViaChange,
}: SelectViaAzureProps) => {
  const router = useRouter();
  const form = useForm<AzureCredentialsTypeFormValues>({
    defaultValues: {
      azureCredentialsType:
        initialVia === "app_certificate" || initialVia === "app_client_secret"
          ? initialVia
          : "",
    },
  });

  const handleSelectionChange = (value: string) => {
    if (onViaChange) {
      onViaChange(value);
      return;
    }

    const url = new URL(window.location.href);
    url.searchParams.set("via", value);
    router.push(url.toString());
  };

  return (
    <Form {...form}>
      <RadioGroupAzureViaCredentialsTypeForm
        control={form.control}
        isInvalid={!!form.formState.errors.azureCredentialsType}
        errorMessage={form.formState.errors.azureCredentialsType?.message}
        onChange={handleSelectionChange}
      />
    </Form>
  );
};
