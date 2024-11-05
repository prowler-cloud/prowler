"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { Control, useForm } from "react-hook-form";
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
  GCPCredentials,
  KubernetesCredentials,
} from "@/types";

import { AWScredentialsForm } from "./via-credentials/aws-credentials-form";
import { AzureCredentialsForm } from "./via-credentials/azure-credentials-form";
import { GCPcredentialsForm } from "./via-credentials/gcp-credentials-form";
import { KubernetesCredentialsForm } from "./via-credentials/k8s-credentials-form";

type CredentialsFormSchema = z.infer<
  ReturnType<typeof addCredentialsFormSchema>
>;

// Add this type intersection to include all fields
type FormType = CredentialsFormSchema &
  AWSCredentials &
  AzureCredentials &
  GCPCredentials &
  KubernetesCredentials;

export const ViaCredentialsForm = ({
  searchParams,
}: {
  searchParams: { type: string; id: string };
}) => {
  const router = useRouter();
  const { toast } = useToast();

  const providerType = searchParams.type;
  const providerId = searchParams.id;
  const formSchema = addCredentialsFormSchema(providerType);

  const form = useForm<FormType>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      secretName: "",
      providerId,
      providerType,
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
            : providerType === "kubernetes"
              ? {
                  kubeconfig_content: "",
                }
              : {}),
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormType) => {
    console.log("via credentials form", values);
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
          case "/data/attributes/secret/client_id":
            form.setError("client_id", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/secret/client_secret":
            form.setError("client_secret", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/secret/tenant_id":
            form.setError("tenant_id", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/secret/kubeconfig_content":
            form.setError("kubeconfig_content", {
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
      router.push(
        `/providers/test-connection?type=${providerType}&id=${providerId}`,
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
          <AWScredentialsForm
            control={form.control as unknown as Control<AWSCredentials>}
          />
        )}
        {providerType === "azure" && (
          <AzureCredentialsForm
            control={form.control as unknown as Control<AzureCredentials>}
          />
        )}
        {providerType === "gcp" && (
          <GCPcredentialsForm
            control={form.control as unknown as Control<GCPCredentials>}
          />
        )}
        {providerType === "kubernetes" && (
          <KubernetesCredentialsForm
            control={form.control as unknown as Control<KubernetesCredentials>}
          />
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
