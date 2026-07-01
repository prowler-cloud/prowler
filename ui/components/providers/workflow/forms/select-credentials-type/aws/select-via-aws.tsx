"use client";

import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { Form } from "@/components/ui/form";

import { RadioGroupAWSViaCredentialsTypeForm } from "./radio-group-aws-via-credentials-type-form";

interface SelectViaAWSProps {
  initialVia?: string;
  onViaChange?: (via: string) => void;
}

export const SelectViaAWS = ({
  initialVia,
  onViaChange,
}: SelectViaAWSProps) => {
  const router = useRouter();
  const form = useForm({
    defaultValues: {
      awsCredentialsType: initialVia || "",
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
      <RadioGroupAWSViaCredentialsTypeForm
        control={form.control}
        isInvalid={!!form.formState.errors.awsCredentialsType}
        errorMessage={form.formState.errors.awsCredentialsType?.message}
        onChange={handleSelectionChange}
      />
    </Form>
  );
};
