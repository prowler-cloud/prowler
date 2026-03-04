"use client";

import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { Form } from "@/components/ui/form";

import { RadioGroupM365ViaCredentialsTypeForm } from "./radio-group-m365-via-credentials-type-form";

interface SelectViaM365Props {
  initialVia?: string;
  onViaChange?: (via: string) => void;
}

export const SelectViaM365 = ({
  initialVia,
  onViaChange,
}: SelectViaM365Props) => {
  const router = useRouter();
  const form = useForm({
    defaultValues: {
      m365CredentialsType: initialVia || "",
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
      <RadioGroupM365ViaCredentialsTypeForm
        control={form.control}
        isInvalid={!!form.formState.errors.m365CredentialsType}
        errorMessage={form.formState.errors.m365CredentialsType?.message}
        onChange={handleSelectionChange}
      />
    </Form>
  );
};
