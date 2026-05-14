"use client";

import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { Form } from "@/components/ui/form";

import { RadioGroupGCPViaCredentialsTypeForm } from "./radio-group-gcp-via-credentials-type-form";

interface SelectViaGCPProps {
  initialVia?: string;
  onViaChange?: (via: string) => void;
}

export const SelectViaGCP = ({
  initialVia,
  onViaChange,
}: SelectViaGCPProps) => {
  const router = useRouter();
  const form = useForm({
    defaultValues: {
      gcpCredentialsType: initialVia || "",
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
      <RadioGroupGCPViaCredentialsTypeForm
        control={form.control}
        isInvalid={!!form.formState.errors.gcpCredentialsType}
        errorMessage={form.formState.errors.gcpCredentialsType?.message}
        onChange={handleSelectionChange}
      />
    </Form>
  );
};
