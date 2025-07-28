"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Divider } from "@nextui-org/react";
import { useSession } from "next-auth/react";
import { useState } from "react";
import { Control, useForm } from "react-hook-form";

import { createIntegration, updateIntegration } from "@/actions/integrations";
import { ProviderSelector } from "@/components/providers/provider-selector";
import { AWSRoleCredentialsForm } from "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-role-credentials-form";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { filterEmptyValues } from "@/lib";
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
}

export const S3IntegrationForm = ({
  integration,
  providers,
  onSuccess,
  onCancel,
}: S3IntegrationFormProps) => {
  const { data: session } = useSession();
  const { toast } = useToast();
  const [currentStep, setCurrentStep] = useState(0);
  const isEditing = !!integration;

  // Create the form with updated schema and default values
  const form = useForm({
    resolver: zodResolver(
      isEditing ? editS3IntegrationFormSchema : s3IntegrationFormSchema,
    ),
    defaultValues: {
      integration_type: "amazon_s3" as const,
      bucket_name: integration?.attributes.configuration.bucket_name || "",
      output_directory:
        integration?.attributes.configuration.output_directory || "",
      providers:
        integration?.relationships?.providers?.data?.map((p) => p.id) || [],
      credentials_type: "aws-sdk-default" as const,
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

  const handleNext = async (e: React.FormEvent) => {
    e.preventDefault(); // Prevent form submission

    // Validate current step fields
    const stepFields =
      currentStep === 0
        ? (["bucket_name", "output_directory", "providers"] as const)
        : (["role_arn", "external_id"] as const);

    const isValid = await form.trigger(stepFields);
    if (isValid) {
      setCurrentStep(1);
    }
  };

  const handleBack = () => {
    setCurrentStep(0);
  };

  const onSubmit = async (values: any) => {
    const formData = new FormData();

    const configuration = {
      bucket_name: values.bucket_name,
      output_directory: values.output_directory,
    };

    // Build credentials object based on credentials_type
    const baseCredentials = {
      role_arn: values.role_arn,
      external_id: values.external_id,
      role_session_name: values.role_session_name,
      session_duration: parseInt(values.session_duration, 10) || 3600,
    };

    // Add static credentials only if using access-secret-key type
    const credentials: any =
      values.credentials_type === "access-secret-key"
        ? filterEmptyValues({
            ...baseCredentials,
            aws_access_key_id: values.aws_access_key_id,
            aws_secret_access_key: values.aws_secret_access_key,
            aws_session_token: values.aws_session_token,
          })
        : filterEmptyValues(baseCredentials);

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

      if ("success" in result) {
        toast({
          title: "Success!",
          description: `S3 integration ${isEditing ? "updated" : "created"} successfully.`,
        });

        if ("testConnection" in result) {
          if (result.testConnection.success) {
            toast({
              title: "Connection Test Started!",
              description:
                "Connection test started. It may take some time to complete.",
            });
          } else if (result.testConnection.error) {
            toast({
              variant: "destructive",
              title: "Connection Test Failed",
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
      console.error(
        `Error ${isEditing ? "updating" : "creating"} S3 integration:`,
        error,
      );

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
    if (currentStep === 0) {
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
              placeholder="/prowler-findings/"
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.output_directory}
            />
          </div>
        </>
      );
    }

    // Step 2: AWS Credentials using AWSRoleCredentialsForm
    return (
      <AWSRoleCredentialsForm
        control={form.control as unknown as Control<AWSCredentialsRole>}
        setValue={form.setValue as any}
        externalId={session?.tenantId || ""}
      />
    );
  };

  const renderStepButtons = () => {
    if (currentStep === 0) {
      return (
        <div className="flex w-full justify-end space-x-4">
          <CustomButton
            type="button"
            ariaLabel="Cancel"
            className="w-1/2 bg-transparent"
            variant="faded"
            size="lg"
            onPress={onCancel}
            isDisabled={isLoading}
          >
            Cancel
          </CustomButton>
          <CustomButton
            type="submit"
            ariaLabel="Next"
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isDisabled={isLoading}
          >
            Next
          </CustomButton>
        </div>
      );
    }

    // Step 2 buttons
    return (
      <div className="flex w-full justify-between space-x-4">
        <CustomButton
          type="button"
          ariaLabel="Back"
          className="w-1/2 bg-transparent"
          variant="faded"
          size="lg"
          onPress={handleBack}
          isDisabled={isLoading}
        >
          Back
        </CustomButton>
        <CustomButton
          type="submit"
          ariaLabel={`${isEditing ? "Update" : "Create"} S3 Integration`}
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
    );
  };

  return (
    <Form {...form}>
      <form
        onSubmit={currentStep === 0 ? handleNext : form.handleSubmit(onSubmit)}
        className="flex flex-col space-y-6"
      >
        <Divider />

        {/* Step Content */}
        <div className="space-y-6">{renderStepContent()}</div>

        {/* Step Buttons */}
        {renderStepButtons()}
      </form>
    </Form>
  );
};
