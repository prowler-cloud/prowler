"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Divider, Switch } from "@nextui-org/react";
import { useSession } from "next-auth/react";
import { useForm } from "react-hook-form";

import { createIntegration, updateIntegration } from "@/actions/integrations";
import { ProviderSelector } from "@/components/integrations/provider-selector";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { filterEmptyValues } from "@/lib";
import { s3IntegrationFormSchema } from "@/types/integrations";
import { IntegrationProps } from "@/types/integrations";
import { ProviderProps } from "@/types/providers";

interface S3IntegrationFormProps {
  integration?: IntegrationProps | null;
  providers: ProviderProps[];
  onSuccess: () => void;
  onCancel: () => void;
}

export const S3IntegrationForm = ({
  integration,
  providers,
  onSuccess,
  onCancel,
}: S3IntegrationFormProps) => {
  const { data: session } = useSession();
  const { toast } = useToast();

  const isEditing = !!integration;

  // Check if the integration has IAM role configured
  const hasIamRole =
    !!integration?.attributes.configuration.credentials?.role_arn;

  const form = useForm({
    resolver: zodResolver(s3IntegrationFormSchema),
    defaultValues: {
      integration_type: "amazon_s3" as const,
      bucket_name: integration?.attributes.configuration.bucket_name || "",
      output_directory:
        integration?.attributes.configuration.output_directory || "",
      providers:
        integration?.relationships?.providers?.data?.map((p) => p.id) || [],
      aws_access_key_id: "",
      aws_secret_access_key: "",
      aws_session_token: "",
      use_iam_role: hasIamRole,
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
  const useIamRole = form.watch("use_iam_role");

  const onSubmit = async (values: any) => {
    const formData = new FormData();

    // Build configuration object for S3 integration
    const configuration = {
      bucket_name: values.bucket_name,
      output_directory: values.output_directory,
    };

    // Build credentials object - always include static credentials
    const credentials: any = filterEmptyValues({
      aws_access_key_id: values.aws_access_key_id,
      aws_secret_access_key: values.aws_secret_access_key,
      aws_session_token: values.aws_session_token,
    });

    // Add IAM role credentials only if the toggle is enabled
    if (values.use_iam_role) {
      Object.assign(
        credentials,
        filterEmptyValues({
          role_arn: values.role_arn,
          external_id: values.external_id,
          role_session_name: values.role_session_name,
          session_duration: parseInt(values.session_duration, 10) || 3600,
        }),
      );
    }

    formData.append("integration_type", values.integration_type);
    formData.append("configuration", JSON.stringify(configuration));
    formData.append("credentials", JSON.stringify(credentials));
    formData.append("providers", JSON.stringify(values.providers));

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

        {/* Provider Selection */}
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">Provider Selection</h3>
          <p className="text-sm text-default-500">
            Select the cloud providers that this integration will export
            findings for.
          </p>

          <ProviderSelector
            control={form.control}
            name="providers"
            providers={providers}
            label="Providers"
            placeholder="Select providers to integrate with"
            isRequired
            isInvalid={!!form.formState.errors.providers}
          />
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
            name="output_directory"
            type="text"
            label="Output Directory"
            labelPlacement="inside"
            placeholder="/prowler-findings/"
            variant="bordered"
            isRequired
            isInvalid={!!form.formState.errors.output_directory}
          />
        </div>

        <Divider />

        {/* AWS Static Credentials - Always visible */}
        <div className="space-y-4">
          <div>
            <h3 className="text-lg font-semibold">AWS Static Credentials</h3>
            <p className="text-sm text-default-500">
              Provide AWS access credentials for the integration.
            </p>
          </div>

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

        <Divider />

        {/* IAM Role Toggle */}
        <div className="space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-lg font-semibold">IAM Role Configuration</h3>
              <p className="text-sm text-default-500">
                Optionally configure IAM role for cross-account access.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm text-default-600">Use IAM Role</span>
              <Switch
                isSelected={useIamRole}
                onValueChange={(value) => form.setValue("use_iam_role", value)}
                color="primary"
                size="sm"
              />
            </div>
          </div>

          {/* IAM Role Fields - Conditional rendering */}
          {useIamRole && (
            <div className="space-y-4">
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
        </div>

        <div className="flex w-full justify-end sm:space-x-6">
          <CustomButton
            type="button"
            ariaLabel="Cancel"
            className="w-1/2 bg-transparent"
            variant="faded"
            size="lg"
            radius="lg"
            onPress={onCancel}
            isDisabled={isLoading}
          >
            Cancel
          </CustomButton>
          <CustomButton
            type="submit"
            ariaLabel={`${isEditing ? "Update" : "Save"} S3 Integration`}
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
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
