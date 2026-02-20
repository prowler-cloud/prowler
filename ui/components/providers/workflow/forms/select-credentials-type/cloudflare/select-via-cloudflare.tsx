"use client";

import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { Form } from "@/components/ui/form";

import { RadioGroupCloudflareViaCredentialsTypeForm } from "./radio-group-cloudflare-via-credentials-type-form";

interface SelectViaCloudflareProps {
  initialVia?: string;
}

export const SelectViaCloudflare = ({
  initialVia,
}: SelectViaCloudflareProps) => {
  const router = useRouter();
  const form = useForm({
    defaultValues: {
      cloudflareCredentialsType: initialVia || "",
    },
  });

  const handleSelectionChange = (value: string) => {
    const url = new URL(window.location.href);
    url.searchParams.set("via", value);
    router.push(url.toString());
  };

  return (
    <Form {...form}>
      <RadioGroupCloudflareViaCredentialsTypeForm
        control={form.control}
        isInvalid={!!form.formState.errors.cloudflareCredentialsType}
        errorMessage={form.formState.errors.cloudflareCredentialsType?.message}
        onChange={handleSelectionChange}
      />
    </Form>
  );
};
