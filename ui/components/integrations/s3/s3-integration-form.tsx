"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Divider } from "@nextui-org/react";
import { ArrowLeftIcon, ArrowRightIcon } from "lucide-react";
import { useSession } from "next-auth/react";
import { useState } from "react";
import { Control, useForm } from "react-hook-form";

import { createIntegration, updateIntegration } from "@/actions/integrations";
import { ProviderSelector } from "@/components/providers/provider-selector";
import { AWSRoleCredentialsForm } from "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-role-credentials-form";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { Form } from "@/components/ui/form";
import { FormButtons } from "@/components/ui/form/form-buttons";
import { getAWSCredentialsTemplateBucketLinks } from "@/lib";
import { AWSCredentialsRole } from "@/types";
import {
  editS3IntegrationFormSchema,
  IntegrationProps,
  s3IntegrationFormSchema,
} from "@/types/integrations";
import { ProviderProps } from "@/types/providers";

interface S3IntegrationFormProps {
  integration?: IntegrationProps | null;
  providers: ProviderProps[];
  onSuccess: () => void;
  onCancel: () => void;
  editMode?: "configuration" | "credentials" | null; // null means creating new
}

export const S3IntegrationForm = ({
  integration,
  providers,
  onSuccess,
  onCancel,
  editMode = null,
}: S3IntegrationFormProps) => {
  const { data: session } = useSession();
  const { toast } = useToast();
  const [currentStep, setCurrentStep] = useState(
    editMode === "credentials" ? 1 : 0,
  );
  const isEditing = !!integration;
  const isCreating = !isEditing;
  const isEditingConfig = editMode === "configuration";
  const isEditingCredentials = editMode === "credentials";

  const form = useForm({
    resolver: zodResolver(
      // For credentials editing, use creation schema (all fields required)
      // For config editing, use edit schema (partial updates allowed)
      // For creation, use creation schema
      isEditingCredentials || isCreating
        ? s3IntegrationFormSchema
        : editS3IntegrationFormSchema,
    ),
    defaultValues: {
      integration_type: "amazon_s3" as const,
      bucket_name: integration?.attributes.configuration.bucket_name || "",
      output_directory:
        integration?.attributes.configuration.output_directory || "output",
      providers:
        integration?.relationships?.providers?.data?.map((p) => p.id) || [],
      enabled: integration?.attributes.enabled ?? true,
      credentials_type: "access-secret-key" as const,
      aws_access_key_id: "",
      aws_secret_access_key: "",
      aws_session_token: "",
      // For credentials editing, show current values as placeholders but require new input
      role_arn: isEditingCredentials
        ? ""
        : integration?.attributes.configuration.credentials?.role_arn || "",
      // External ID always defaults to tenantId, even when editing credentials
      external_id:
        integration?.attributes.configuration.credentials?.external_id ||
        session?.tenantId ||
        "",
      role_session_name: "",
      session_duration: "",
    },
  });

  const isLoading = form.formState.isSubmitting;

  const handleNext = async (e: React.FormEvent) => {
    e.preventDefault();

    // If we're in single-step edit mode, don't advance
    if (isEditingConfig || isEditingCredentials) {
      return;
    }

    // Validate current step fields for creation flow
    const stepFields =
      currentStep === 0
        ? (["bucket_name", "output_directory", "providers"] as const)
        : // Step 1: No required fields since role_arn and external_id are optional
          [];

    const isValid = stepFields.length === 0 || (await form.trigger(stepFields));

    if (isValid) {
      setCurrentStep(1);
    }
  };

  const handleBack = () => {
    setCurrentStep(0);
  };

  // Helper function to build credentials object
  const buildCredentials = (values: any) => {
    const credentials: any = {};

    // Only include role-related fields if role_arn is provided
    if (values.role_arn && values.role_arn.trim() !== "") {
      credentials.role_arn = values.role_arn;
      credentials.external_id = values.external_id;

      // Optional role fields
      if (values.role_session_name)
        credentials.role_session_name = values.role_session_name;
      if (values.session_duration)
        credentials.session_duration =
          parseInt(values.session_duration, 10) || 3600;
    }

    // Add static credentials if using access-secret-key type
    if (values.credentials_type === "access-secret-key") {
      credentials.aws_access_key_id = values.aws_access_key_id;
      credentials.aws_secret_access_key = values.aws_secret_access_key;
      if (values.aws_session_token)
        credentials.aws_session_token = values.aws_session_token;
    }

    return credentials;
  };

  const buildConfiguration = (values: any, isPartial = false) => {
    const configuration: any = {};

    // For creation mode, include all fields
    if (!isPartial) {
      configuration.bucket_name = values.bucket_name;
      configuration.output_directory = values.output_directory || "output";
    } else {
      // For edit mode, bucket_name and output_directory are treated as a pair
      const originalBucketName =
        integration?.attributes.configuration.bucket_name || "";
      const originalOutputDirectory =
        integration?.attributes.configuration.output_directory || "";

      const bucketNameChanged = values.bucket_name !== originalBucketName;
      const outputDirectoryChanged =
        values.output_directory !== originalOutputDirectory;

      // If either field changed, send both (as a pair)
      if (bucketNameChanged || outputDirectoryChanged) {
        configuration.bucket_name = values.bucket_name;
        configuration.output_directory = values.output_directory || "output";
      }
    }

    return configuration;
  };

  // Helper function to build FormData based on edit mode
  const buildFormData = (values: any) => {
    const formData = new FormData();
    formData.append("integration_type", values.integration_type);

    if (isEditingConfig) {
      const configuration = buildConfiguration(values, true);
      if (Object.keys(configuration).length > 0) {
        formData.append("configuration", JSON.stringify(configuration));
      }
      // Always send providers array, even if empty, to update relationships
      formData.append("providers", JSON.stringify(values.providers || []));
    } else if (isEditingCredentials) {
      const credentials = buildCredentials(values);
      formData.append("credentials", JSON.stringify(credentials));
    } else {
      // Creation mode - send everything
      const configuration = buildConfiguration(values);
      const credentials = buildCredentials(values);

      formData.append("configuration", JSON.stringify(configuration));
      formData.append("credentials", JSON.stringify(credentials));
      formData.append("providers", JSON.stringify(values.providers));
      formData.append("enabled", JSON.stringify(values.enabled ?? true));
    }

    return formData;
  };

  const onSubmit = async (values: any) => {
    const formData = buildFormData(values);

    try {
      let result;
      if (isEditing && integration) {
        result = await updateIntegration(integration.id, formData);
      } else {
        result = await createIntegration(formData);
      }

      if ("success" in result) {
        toast({
          title: "Success!",
          description: `S3 integration ${isEditing ? "updated" : "created"} successfully.`,
        });

        if ("testConnection" in result) {
          if (result.testConnection.success) {
            toast({
              title: "Connection test started!",
              description:
                "Connection test started. It may take some time to complete.",
            });
          } else if (result.testConnection.error) {
            toast({
              variant: "destructive",
              title: "Connection test failed",
              description: result.testConnection.error,
            });
          }
        }

        onSuccess();
      } else if ("error" in result) {
        const errorMessage = result.error;

        toast({
          variant: "destructive",
          title: "S3 Integration Error",
          description: errorMessage,
        });
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "An unexpected error occurred";

      toast({
        variant: "destructive",
        title: "Connection Error",
        description: `${errorMessage}. Please check your network connection and try again.`,
      });
    }
  };

  const renderStepContent = () => {
    // If editing credentials, show only credentials form
    if (isEditingCredentials || currentStep === 1) {
      const bucketName = form.getValues("bucket_name") || "";
      const externalId =
        form.getValues("external_id") || session?.tenantId || "";
      const templateLinks = getAWSCredentialsTemplateBucketLinks(
        bucketName,
        externalId,
      );

      return (
        <AWSRoleCredentialsForm
          control={form.control as unknown as Control<AWSCredentialsRole>}
          setValue={form.setValue as any}
          externalId={externalId}
          templateLinks={templateLinks}
          type="s3-integration"
        />
      );
    }

    // Show configuration step (step 0 or editing configuration)
    if (isEditingConfig || currentStep === 0) {
      return (
        <>
          {/* Provider Selection */}
          <div className="space-y-4">
            <ProviderSelector
              control={form.control}
              name="providers"
              providers={providers}
              label="Cloud Providers"
              placeholder="Select providers to integrate with"
              isInvalid={!!form.formState.errors.providers}
            />
          </div>

          <Divider />

          {/* S3 Configuration */}
          <div className="space-y-4">
            <CustomInput
              control={form.control}
              name="bucket_name"
              type="text"
              label="Bucket name"
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
              label="Output directory"
              labelPlacement="inside"
              placeholder="output"
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.output_directory}
            />
          </div>
        </>
      );
    }

    return null;
  };

  const renderStepButtons = () => {
    // Single edit mode (configuration or credentials)
    if (isEditingConfig || isEditingCredentials) {
      const updateText = isEditingConfig
        ? "Update Configuration"
        : "Update Credentials";
      const loadingText = isEditingConfig
        ? "Updating Configuration..."
        : "Updating Credentials...";

      return (
        <FormButtons
          setIsOpen={() => {}}
          onCancel={onCancel}
          submitText={updateText}
          cancelText="Cancel"
          loadingText={loadingText}
          isDisabled={isLoading}
        />
      );
    }

    // Creation flow - step 0
    if (currentStep === 0) {
      return (
        <FormButtons
          setIsOpen={() => {}}
          onCancel={onCancel}
          submitText="Next"
          cancelText="Cancel"
          loadingText="Processing..."
          isDisabled={isLoading}
          rightIcon={<ArrowRightIcon size={24} />}
        />
      );
    }

    // Creation flow - step 1 (final step)
    return (
      <FormButtons
        setIsOpen={() => {}}
        onCancel={handleBack}
        submitText="Create Integration"
        cancelText="Back"
        loadingText="Creating..."
        leftIcon={<ArrowLeftIcon size={24} />}
        isDisabled={isLoading}
      />
    );
  };

  return (
    <Form {...form}>
      <form
        onSubmit={
          // For edit modes, always submit
          isEditingConfig || isEditingCredentials
            ? form.handleSubmit(onSubmit)
            : // For creation flow, handle step logic
              currentStep === 0
              ? handleNext
              : form.handleSubmit(onSubmit)
        }
        className="flex flex-col space-y-6"
      >
        <div className="flex flex-col space-y-4">
          <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
            <p className="flex items-center gap-2 text-sm text-default-500">
              Need help configuring your Amazon S3 integrations?
            </p>
            <CustomLink
              href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-s3-integration/"
              target="_blank"
              size="sm"
            >
              Read the docs
            </CustomLink>
          </div>
          {renderStepContent()}
        </div>
        {renderStepButtons()}
      </form>
    </Form>
  );
};
