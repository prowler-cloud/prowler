"use client";

import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { Form } from "@/components/ui/form";

import { RadioGroupGitHubViaCredentialsTypeForm } from "./radio-group-github-via-credentials-type-form";

interface SelectViaGitHubProps {
  initialVia?: string;
}

export const SelectViaGitHub = ({ initialVia }: SelectViaGitHubProps) => {
  const router = useRouter();
  const form = useForm({
    defaultValues: {
      githubCredentialsType: initialVia || "",
    },
  });

  const handleSelectionChange = (value: string) => {
    const url = new URL(window.location.href);
    url.searchParams.set("via", value);
    router.push(url.toString());
  };

  return (
    <Form {...form}>
      <RadioGroupGitHubViaCredentialsTypeForm
        control={form.control}
        isInvalid={!!form.formState.errors.githubCredentialsType}
        errorMessage={form.formState.errors.githubCredentialsType?.message}
        onChange={handleSelectionChange}
      />
    </Form>
  );
};
