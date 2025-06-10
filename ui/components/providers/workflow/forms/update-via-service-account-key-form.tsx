"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Divider } from "@nextui-org/react";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Control, useForm } from "react-hook-form";
import * as z from "zod";

import { updateCredentialsProvider } from "@/actions/providers/providers";
import { ProviderTitleDocs } from "@/components/providers/workflow";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import {
  addCredentialsServiceAccountFormSchema,
  ApiError,
  GCPServiceAccountKey,
  ProviderType,
} from "@/types";

import { GCPServiceAccountKeyForm } from "./select-credentials-type/gcp/credentials-type";

export const UpdateViaServiceAccountForm = ({
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

  const providerType = searchParams.type as ProviderType;
  const providerId = searchParams.id;
  const providerSecretId = searchParams.secretId || "";

  const formSchema = addCredentialsServiceAccountFormSchema(providerType);
  type FormSchemaType = z.infer<typeof formSchema>;

  const form = useForm<FormSchemaType>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId,
      providerType,
      ...(providerType === "gcp"
        ? {
            service_account_key: "",
            secretName: "",
          }
        : {}),
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormSchemaType) => {
    if (!providerSecretId) {
      toast({
        variant: "destructive",
        title: "Missing Secret ID",
        description: "Cannot update credentials without a valid secret ID.",
      });
      return;
    }

    const formData = new FormData();

    Object.entries(values).forEach(([key, value]) => {
      if (value !== undefined && value !== "") {
        formData.append(key, String(value));
      }
    });

    try {
      const data = await updateCredentialsProvider(providerSecretId, formData);
      if (data?.errors && data.errors.length > 0) {
        data.errors.forEach((error: ApiError) => {
          const errorMessage = error.detail;

          switch (error.source.pointer) {
            case "/data/attributes/secret/service_account_key":
              form.setError("service_account_key" as keyof FormSchemaType, {
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

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <input type="hidden" name="providerId" value={providerId} />
        <input type="hidden" name="providerType" value={providerType} />

        <ProviderTitleDocs providerType={providerType} />

        <Divider />

        {providerType === "gcp" && (
          <GCPServiceAccountKeyForm
            control={form.control as unknown as Control<GCPServiceAccountKey>}
          />
        )}

        <div className="flex w-full justify-end sm:space-x-6">
          {searchParamsObj.get("via") === "service-account" && (
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
