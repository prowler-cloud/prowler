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

import { AWSRoleCredentialsForm } from "./select-credentials-type/aws/credentials-type";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

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
    [ProviderCredentialFields.CREDENTIALS_TYPE]:
      | typeof ProviderCredentialFields.CREDENTIALS_TYPE_AWS
      | typeof ProviderCredentialFields.CREDENTIALS_TYPE_ACCESS_SECRET_KEY;
  };

  const form = useForm<FormSchemaType>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId,
      providerType,
      credentials_type: ProviderCredentialFields.CREDENTIALS_TYPE_AWS,
      ...(providerType === "aws" && {
        [ProviderCredentialFields.ROLE_ARN]: "",
        [ProviderCredentialFields.EXTERNAL_ID]: externalId,
        [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "",
        [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: "",
        [ProviderCredentialFields.AWS_SESSION_TOKEN]: "",
        [ProviderCredentialFields.ROLE_SESSION_NAME]: "",
        [ProviderCredentialFields.SESSION_DURATION]: "3600",
      }),
    },
  });

  const isLoading = form.formState.isSubmitting;

  // Handle form submission
  const onSubmitClient = async (values: FormSchemaType) => {
    try {
      const formData = new FormData();

      Object.entries(values).forEach(([key, value]) => {
        if (key === ProviderCredentialFields.CREDENTIALS_TYPE) return;

        if (
          values[ProviderCredentialFields.CREDENTIALS_TYPE] ===
            ProviderCredentialFields.CREDENTIALS_TYPE_ACCESS_SECRET_KEY &&
          [
            ProviderCredentialFields.AWS_ACCESS_KEY_ID,
            ProviderCredentialFields.AWS_SECRET_ACCESS_KEY,
            ProviderCredentialFields.AWS_SESSION_TOKEN,
          ].includes(
            key as
              | typeof ProviderCredentialFields.AWS_ACCESS_KEY_ID
              | typeof ProviderCredentialFields.AWS_SECRET_ACCESS_KEY
              | typeof ProviderCredentialFields.AWS_SESSION_TOKEN,
          )
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
          <AWSRoleCredentialsForm
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
