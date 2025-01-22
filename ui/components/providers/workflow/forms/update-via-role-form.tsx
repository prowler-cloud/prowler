"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useSession } from "next-auth/react";
import { Control, useForm, UseFormSetValue } from "react-hook-form";
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
  const { data: session } = useSession();

  const searchParamsObj = useSearchParams();

  // Extract values from searchParams
  const providerType = searchParams.type;
  const providerId = searchParams.id;
  const providerSecretId = searchParams.secretId || "";
  const externalId = session?.tenantId;

  const formSchema = addCredentialsRoleFormSchema(providerType);
  type FormSchemaType = z.infer<typeof formSchema> & {
    credentials_type: "aws-sdk-default" | "access-secret-key";
  };

  const form = useForm<FormSchemaType>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId,
      providerType,
      credentials_type: "aws-sdk-default",
      ...(providerType === "aws" && {
        role_arn: "",
        external_id: externalId,
        aws_access_key_id: "",
        aws_secret_access_key: "",
        aws_session_token: "",
        role_session_name: "",
        session_duration: 3600,
      }),
    },
  });

  const isLoading = form.formState.isSubmitting;

  // Handle form submission
  const onSubmitClient = async (values: FormSchemaType) => {
    try {
      const formData = new FormData();

      Object.entries(values).forEach(([key, value]) => {
        if (key === "credentials_type") return;

        if (
          values.credentials_type === "access-secret-key" &&
          [
            "aws_access_key_id",
            "aws_secret_access_key",
            "aws_session_token",
          ].includes(key)
        ) {
          if (value !== undefined && value !== "") {
            formData.append(key, String(value));
          }
          return;
        }

        if (value !== undefined && value !== "") {
          formData.append(key, String(value));
        }
      });

      const data = await updateCredentialsProvider(providerSecretId, formData);

      // Handle errors
      if (data?.errors?.length) {
        data.errors.forEach((error: ApiError) => {
          const errorMessage = error.detail;
          switch (error.source.pointer) {
            case "/data/attributes/secret/role_arn":
              form.setError("role_arn" as keyof FormSchemaType, {
                type: "server",
                message: errorMessage,
              });
              break;
            case "/data/attributes/secret/external_id":
              form.setError("external_id" as keyof FormSchemaType, {
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
        // Redirect on success
        router.push(
          `/providers/test-connection?type=${providerType}&id=${providerId}&updated=true`,
        );
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("Error during submission:", error);
      toast({
        variant: "destructive",
        title: "Submission failed",
        description: "An error occurred while processing your request.",
      });
    }
  };

  // Handle back navigation
  const handleBackStep = () => {
    const currentParams = new URLSearchParams(window.location.search);
    currentParams.delete("via");
    router.push(`?${currentParams.toString()}`);
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <input type="hidden" name="providerId" value={providerId} />
        <input type="hidden" name="providerType" value={providerType} />

        {/* Conditional AWS Form */}
        {providerType === "aws" && (
          <AWSCredentialsRoleForm
            control={form.control as unknown as Control<AWSCredentialsRole>}
            setValue={
              form.setValue as unknown as UseFormSetValue<AWSCredentialsRole>
            }
            externalId={externalId || ""}
          />
        )}

        {/* Action Buttons */}
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
            ariaLabel="Save"
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
