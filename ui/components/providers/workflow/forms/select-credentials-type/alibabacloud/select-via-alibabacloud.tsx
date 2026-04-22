"use client";

import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { Form } from "@/components/ui/form";

import { RadioGroupAlibabaCloudViaCredentialsTypeForm } from "./radio-group-alibabacloud-via-credentials-type-form";

interface SelectViaAlibabaCloudProps {
  initialVia?: string;
  onViaChange?: (via: string) => void;
}

export const SelectViaAlibabaCloud = ({
  initialVia,
  onViaChange,
}: SelectViaAlibabaCloudProps) => {
  const router = useRouter();
  const form = useForm({
    defaultValues: {
      alibabacloudCredentialsType: initialVia || "",
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
      <RadioGroupAlibabaCloudViaCredentialsTypeForm
        control={form.control}
        isInvalid={!!form.formState.errors.alibabacloudCredentialsType}
        errorMessage={
          form.formState.errors.alibabacloudCredentialsType?.message as string
        }
        onChange={handleSelectionChange}
      />
    </Form>
  );
};
