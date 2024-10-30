"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { FieldErrors, useForm } from "react-hook-form";
import * as z from "zod";

import { addCredentialsProvider } from "@/actions/providers/providers";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";

import {
  addCredentialsFormSchema,
  ApiError,
  AWSCredentials,
  CredentialsFormSchema,
} from "../../../../types";

export const AddCredentialsForm = ({
  searchParams,
}: {
  searchParams: { provider: string; id: string };
}) => {
  const providerType = searchParams.provider;
  const providerId = searchParams.id;

  const formSchema = addCredentialsFormSchema(providerType);

  const { toast } = useToast();
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

  const router = useRouter();

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
        <CustomInput
          control={form.control}
          name="secretName"
          type="text"
          label="Secret Name"
          labelPlacement="inside"
          placeholder={"Enter the Secret Name"}
          variant="bordered"
          isRequired={false}
          isInvalid={!!form.formState.errors.secretName}
        />
        {providerType === "aws" && (
          <>
            <CustomInput
              control={form.control}
              name="aws_access_key_id"
              type="text"
              label="AWS Access Key ID"
              labelPlacement="inside"
              placeholder="Enter the AWS Access Key ID"
              variant="bordered"
              isRequired
              isInvalid={
                !!(form.formState.errors as FieldErrors<AWSCredentials>)
                  .aws_access_key_id
              }
            />
            <CustomInput
              control={form.control}
              name="aws_secret_access_key"
              type="text"
              label="AWS Secret Access Key"
              labelPlacement="inside"
              placeholder="Enter the AWS Secret Access Key"
              variant="bordered"
              isRequired
              isInvalid={
                !!(form.formState.errors as FieldErrors<AWSCredentials>)
                  .aws_secret_access_key
              }
            />
            <CustomInput
              control={form.control}
              name="aws_session_token"
              type="text"
              label="AWS Session Token"
              labelPlacement="inside"
              placeholder="Enter the AWS Session Token"
              variant="bordered"
              isRequired
              isInvalid={
                !!(form.formState.errors as FieldErrors<AWSCredentials>)
                  .aws_session_token
              }
            />
          </>
        )}

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
