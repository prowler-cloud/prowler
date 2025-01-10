"use client";

import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { Form } from "@/components/ui/form";

import { RadioGroupAWSViaCredentialsForm } from "../radio-group-aws-via-credentials-form";

interface SelectViaAWSProps {
  initialVia?: string;
}

export const SelectViaAWS = ({ initialVia }: SelectViaAWSProps) => {
  const router = useRouter();
  const form = useForm({
    defaultValues: {
      awsCredentialsType: initialVia || "",
    },
  });

  const handleSelectionChange = (value: string) => {
    const url = new URL(window.location.href);
    url.searchParams.set("via", value);
    router.push(url.toString());
  };

  return (
    <Form {...form}>
      <RadioGroupAWSViaCredentialsForm
        control={form.control}
        isInvalid={!!form.formState.errors.awsCredentialsType}
        errorMessage={form.formState.errors.awsCredentialsType?.message}
        onChange={handleSelectionChange}
      />
    </Form>
  );
};
