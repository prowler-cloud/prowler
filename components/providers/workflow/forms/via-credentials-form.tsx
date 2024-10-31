"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { Control, FieldErrors, useForm } from "react-hook-form";
import * as z from "zod";

import { addCredentialsProvider } from "@/actions/providers/providers";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";

import {
  addCredentialsFormSchema,
  ApiError,
  AWSCredentials,
  AzureCredentials,
  CredentialsFormSchema,
} from "../../../../types";
import { AWScredentialsForm } from "./via-credentials/aws-credentials-form";

export const ViaCredentialsForm = ({
  searchParams,
}: {
  searchParams: { provider: string; id: string };
}) => {
  const router = useRouter();
  const { toast } = useToast();

  const providerType = searchParams.provider;
  const providerId = searchParams.id;

  const formSchema = addCredentialsFormSchema(providerType);

  const form = useForm<CredentialsFormSchema>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      secretName: "",
      providerId,
      ...(providerType === "aws"
        ? {
            aws_access_key_id: "",
            aws_secret_access_key: "",
            aws_session_token: "",
          }
        : providerType === "azure"
          ? {
              client_id: "",
              client_secret: "",
              tenant_id: "",
            }
          : providerType === "gcp"
            ? {
                client_id: "",
                client_secret: "",
                refresh_token: "",
              }
            : {}),
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    const data = await addCredentialsProvider(formData);

    if (data?.errors && data.errors.length > 0) {
      data.errors.forEach((error: ApiError) => {
        const errorMessage = error.detail;
        switch (error.source.pointer) {
          case "/data/attributes/secret/aws_access_key_id":
            form.setError("aws_access_key_id", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/secret/aws_secret_access_key":
            form.setError("aws_secret_access_key", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/secret/aws_session_token":
            form.setError("aws_session_token", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/name":
            form.setError("secretName", {
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
      router.push("/providers/test-connection");
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <input type="hidden" name="providerId" value={providerId} />

        {providerType === "aws" && (
          <AWScredentialsForm
            control={form.control as Control<AWSCredentials>}
          />
        )}
        {providerType === "azure" && (
          <>
            <div className="text-left">
              <div className="text-2xl font-bold leading-9 text-default-foreground">
                Connect via Credentials
              </div>
              <div className="py-2 text-default-500">
                Please provide the information for your Azure credentials.
              </div>
            </div>
            <CustomInput
              control={form.control}
              name="client_id"
              type="text"
              label="Client ID"
              labelPlacement="inside"
              placeholder="Enter the Client ID"
              variant="bordered"
              isRequired
              isInvalid={
                !!(form.formState.errors as FieldErrors<AzureCredentials>)
                  .client_id
              }
            />
            <CustomInput
              control={form.control}
              name="client_secret"
              type="text"
              label="Client Secret"
              labelPlacement="inside"
              placeholder="Enter the Client Secret"
              variant="bordered"
              isRequired
              isInvalid={
                !!(form.formState.errors as FieldErrors<AzureCredentials>)
                  .client_secret
              }
            />
            <CustomInput
              control={form.control}
              name="tenant_id"
              type="text"
              label="Tenant ID"
              labelPlacement="inside"
              placeholder="Enter the Tenant ID"
              variant="bordered"
              isRequired
              isInvalid={
                !!(form.formState.errors as FieldErrors<AzureCredentials>)
                  .tenant_id
              }
            />
          </>
        )}
        <span className="text-sm text-default-500">Name (Optional)</span>
        <CustomInput
          control={form.control}
          name="secretName"
          type="text"
          label="Credential name"
          labelPlacement="inside"
          placeholder={"Enter the credential name"}
          variant="bordered"
          isRequired={false}
          size="sm"
          isInvalid={!!form.formState.errors.secretName}
        />

        <div className="flex w-full justify-end sm:space-x-6">
          <CustomButton
            type="submit"
            ariaLabel={"Save"}
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <SaveIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Save</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
