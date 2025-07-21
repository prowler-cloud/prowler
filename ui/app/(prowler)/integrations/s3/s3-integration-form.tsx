"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Divider } from "@nextui-org/react";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { useSession } from "next-auth/react";
import { useForm } from "react-hook-form";

import { createIntegration, updateIntegration } from "@/actions/integrations";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { filterEmptyValues } from "@/lib";
import { s3IntegrationFormSchema } from "@/types/integrations";
import { IntegrationProps } from "@/types/integrations";

interface S3IntegrationFormProps {
  integration?: IntegrationProps | null;
  onSuccess: () => void;
  onCancel: () => void;
}

export const S3IntegrationForm = ({
  integration,
  onSuccess,
  onCancel,
}: S3IntegrationFormProps) => {
  const { data: session } = useSession();
  const { toast } = useToast();

  const isEditing = !!integration;

  const form = useForm({
    resolver: zodResolver(s3IntegrationFormSchema),
    defaultValues: {
      integration_type: "amazon_s3" as const,
      bucket_name: integration?.attributes.configuration.bucket_name || "",
      path: integration?.attributes.configuration.path || "",
      credentials_type: integration?.attributes.configuration.credentials
        ?.role_arn
        ? ("role" as const)
        : ("static" as const),
      aws_access_key_id: "",
      aws_secret_access_key: "",
      aws_session_token: "",
      role_arn:
        integration?.attributes.configuration.credentials?.role_arn || "",
      external_id:
        integration?.attributes.configuration.credentials?.external_id ||
        session?.tenantId ||
        "",
      role_session_name:
        integration?.attributes.configuration.credentials?.role_session_name ||
        "",
      session_duration:
        integration?.attributes.configuration.credentials?.session_duration?.toString() ||
        "3600",
    },
  });

  const isLoading = form.formState.isSubmitting;
  const credentialsType = form.watch("credentials_type");

  const onSubmit = async (values: any) => {
    const formData = new FormData();

    // Build configuration object for S3 integration
    const configuration = {
      bucket_name: values.bucket_name,
      path: values.path || "/",
      credentials: {} as any,
    };

    // Add credentials based on type
    if (credentialsType === "static") {
      configuration.credentials = filterEmptyValues({
        aws_access_key_id: values.aws_access_key_id,
        aws_secret_access_key: values.aws_secret_access_key,
        aws_session_token: values.aws_session_token,
      });
    } else if (credentialsType === "role") {
      configuration.credentials = filterEmptyValues({
        role_arn: values.role_arn,
        external_id: values.external_id,
        role_session_name: values.role_session_name,
        session_duration: parseInt(values.session_duration, 10) || 3600,
      });
    }

    formData.append("integration_type", values.integration_type);
    formData.append("configuration", JSON.stringify(configuration));

    try {
      let result;
      if (isEditing && integration) {
        result = await updateIntegration(integration.id, formData);
      } else {
        result = await createIntegration(formData);
      }

      if (result.success) {
        toast({
          title: "Success!",
          description: `S3 integration ${isEditing ? "updated" : "created"} successfully.`,
        });
        onSuccess();
      } else if (result.errors) {
        toast({
          variant: "destructive",
          title: "Error",
          description: `Failed to ${isEditing ? "update" : "create"} S3 integration. Please check your credentials.`,
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "An unexpected error occurred. Please try again.",
      });
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className="flex flex-col space-y-4"
      >
        <div className="flex flex-col">
          <div className="text-md font-bold leading-9 text-default-foreground">
            {isEditing ? "Update" : "Configure"} Amazon S3 Integration
          </div>
          <div className="text-sm text-default-500">
            Export your security findings to Amazon S3 buckets automatically.
          </div>
        </div>

        <Divider />

        {/* S3 Configuration */}
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">S3 Configuration</h3>

          <CustomInput
            control={form.control}
            name="bucket_name"
            type="text"
            label="S3 Bucket Name"
            labelPlacement="inside"
            placeholder="my-security-findings-bucket"
            variant="bordered"
            isRequired
            isInvalid={!!form.formState.errors.bucket_name}
          />

          <CustomInput
            control={form.control}
            name="path"
            type="text"
            label="Path (optional)"
            labelPlacement="inside"
            placeholder="/prowler-findings/"
            variant="bordered"
            isRequired={false}
            isInvalid={!!form.formState.errors.path}
          />
        </div>

        <Divider />

        {/* Credentials Type Selection */}
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">Authentication Method</h3>

          <div className="flex gap-4">
            <CustomButton
              type="button"
              variant={credentialsType === "static" ? "solid" : "bordered"}
              color={credentialsType === "static" ? "action" : "secondary"}
              onPress={() => form.setValue("credentials_type", "static")}
              ariaLabel="Use static credentials"
            >
              Static Credentials
            </CustomButton>
            <CustomButton
              type="button"
              variant={credentialsType === "role" ? "solid" : "bordered"}
              color={credentialsType === "role" ? "action" : "secondary"}
              onPress={() => form.setValue("credentials_type", "role")}
              ariaLabel="Use IAM role"
            >
              IAM Role
            </CustomButton>
          </div>
        </div>

        <Divider />

        {/* Credentials Form */}
        {credentialsType === "static" && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">AWS Credentials</h3>

            <CustomInput
              control={form.control}
              name="aws_access_key_id"
              type="password"
              label="AWS Access Key ID"
              labelPlacement="inside"
              placeholder="Enter the AWS Access Key ID"
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.aws_access_key_id}
            />

            <CustomInput
              control={form.control}
              name="aws_secret_access_key"
              type="password"
              label="AWS Secret Access Key"
              labelPlacement="inside"
              placeholder="Enter the AWS Secret Access Key"
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.aws_secret_access_key}
            />

            <CustomInput
              control={form.control}
              name="aws_session_token"
              type="password"
              label="AWS Session Token (optional)"
              labelPlacement="inside"
              placeholder="Enter the AWS Session Token"
              variant="bordered"
              isRequired={false}
              isInvalid={!!form.formState.errors.aws_session_token}
            />
          </div>
        )}

        {credentialsType === "role" && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">IAM Role Configuration</h3>

            <CustomInput
              control={form.control}
              name="role_arn"
              type="text"
              label="Role ARN"
              labelPlacement="inside"
              placeholder="arn:aws:iam::123456789012:role/ProwlerRole"
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.role_arn}
            />

            <CustomInput
              control={form.control}
              name="external_id"
              type="text"
              label="External ID"
              labelPlacement="inside"
              placeholder="Enter the External ID"
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.external_id}
            />

            <CustomInput
              control={form.control}
              name="role_session_name"
              type="text"
              label="Role Session Name (optional)"
              labelPlacement="inside"
              placeholder="ProwlerSession"
              variant="bordered"
              isRequired={false}
              isInvalid={!!form.formState.errors.role_session_name}
            />

            <CustomInput
              control={form.control}
              name="session_duration"
              type="number"
              label="Session Duration (seconds)"
              labelPlacement="inside"
              placeholder="3600"
              variant="bordered"
              isRequired={false}
              isInvalid={!!form.formState.errors.session_duration}
            />
          </div>
        )}

        <div className="flex w-full justify-end sm:space-x-6">
          <CustomButton
            type="button"
            ariaLabel="Cancel"
            className="w-1/2 bg-transparent"
            variant="faded"
            size="lg"
            radius="lg"
            onPress={onCancel}
            startContent={!isLoading && <ChevronLeftIcon size={24} />}
            isDisabled={isLoading}
          >
            <span>Cancel</span>
          </CustomButton>
          <CustomButton
            type="submit"
            ariaLabel={`${isEditing ? "Update" : "Save"} S3 Integration`}
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            endContent={!isLoading && <ChevronRightIcon size={24} />}
          >
            {isLoading ? (
              <>{isEditing ? "Updating..." : "Creating..."}</>
            ) : (
              <span>
                {isEditing ? "Update Integration" : "Create Integration"}
              </span>
            )}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
