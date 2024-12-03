"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Control, useForm } from "react-hook-form";
import * as z from "zod";

import { updateCredentialsProvider } from "@/actions/providers/providers";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import {
  addCredentialsRoleFormSchema,
  ApiError,
  AWSCredentialsRole,
} from "@/types";

import { AWSCredentialsRoleForm } from "./via-role/aws-role-form";

export const UpdateViaRoleForm = ({
  searchParams,
}: {
  searchParams: { type: string; id: string; secretId?: string };
}) => {
  const router = useRouter();
  const { toast } = useToast();

  const searchParamsObj = useSearchParams();

  // Handler for back button
  const handleBackStep = () => {
    const currentParams = new URLSearchParams(window.location.search);
    currentParams.delete("via");
    router.push(`?${currentParams.toString()}`);
  };

  const providerType = searchParams.type;
  const providerId = searchParams.id;
  const providerSecretId = searchParams.secretId || "";

  const formSchema = addCredentialsRoleFormSchema(providerType);
  type FormSchemaType = z.infer<typeof formSchema>;

  const form = useForm<FormSchemaType>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId,
      providerType,
      ...(providerType === "aws"
        ? {
            role_arn: "",
            aws_access_key_id: "",
            aws_secret_access_key: "",
            aws_session_token: "",
            session_duration: 3600,
            external_id: "",
            role_session_name: "",
          }
        : {}),
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormSchemaType) => {
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) =>
        value !== undefined && formData.append(key, String(value)),
    );

    const data = await updateCredentialsProvider(providerSecretId, formData);

    if (data?.errors && data.errors.length > 0) {
      data.errors.forEach((error: ApiError) => {
        const errorMessage = error.detail;
        switch (error.source.pointer) {
          case "/data/attributes/secret/role_arn":
            form.setError("role_arn" as keyof FormSchemaType, {
              type: "server",
              message: errorMessage,
            });
            break;

          default:
            toast({
              variant: "destructive",
              title: "Oops! Something went wrong",
              description: errorMessage,
            });
        }
      });
    } else {
      router.push(
        `/providers/test-connection?type=${providerType}&id=${providerId}&updated=true`,
      );
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <input type="hidden" name="providerId" value={providerId} />
        <input type="hidden" name="providerType" value={providerType} />

        {providerType === "aws" && (
          <AWSCredentialsRoleForm
            control={form.control as unknown as Control<AWSCredentialsRole>}
          />
        )}

        <div className="flex w-full justify-end sm:space-x-6">
          {searchParamsObj.get("via") === "role" && (
            <CustomButton
              type="button"
              ariaLabel="Back"
              className="w-1/2 bg-transparent"
              variant="faded"
              size="lg"
              radius="lg"
              onPress={handleBackStep}
              startContent={!isLoading && <ChevronLeftIcon size={24} />}
              isDisabled={isLoading}
            >
              <span>Back</span>
            </CustomButton>
          )}
          <CustomButton
            type="submit"
            ariaLabel={"Save"}
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            endContent={!isLoading && <ChevronRightIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Next</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
