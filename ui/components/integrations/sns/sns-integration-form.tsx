"use client";

import { Checkbox } from "@heroui/checkbox";
import { Divider } from "@heroui/divider";
import { Radio, RadioGroup } from "@heroui/radio";
import { zodResolver } from "@hookform/resolvers/zod";
import { useSession } from "next-auth/react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { createIntegration, updateIntegration } from "@/actions/integrations";
import { AWSRoleCredentialsForm } from "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-role-credentials-form";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { Form, FormControl, FormField } from "@/components/ui/form";
import { FormButtons } from "@/components/ui/form/form-buttons";
import { getAWSCredentialsTemplateLinks } from "@/lib";
import {
  editSNSIntegrationFormSchema,
  IntegrationProps,
  snsIntegrationFormSchema,
  type SNSCredentialsPayload,
} from "@/types/integrations";

interface SNSIntegrationFormProps {
  integration?: IntegrationProps | null;
  onSuccess: (integrationId?: string, shouldTestConnection?: boolean) => void;
  onCancel: () => void;
  editMode?: "configuration" | "credentials" | null;
}

export const SNSIntegrationForm = ({
  integration,
  onSuccess,
  onCancel,
  editMode = null,
}: SNSIntegrationFormProps) => {
  const { data: session } = useSession();
  const { toast } = useToast();
  const isEditing = !!integration;
  const isCreating = !isEditing;
  const isEditingConfig = editMode === "configuration";
  const isEditingCredentials = editMode === "credentials";

  const form = useForm({
    resolver: zodResolver(
      isEditingCredentials || isCreating
        ? snsIntegrationFormSchema
        : editSNSIntegrationFormSchema,
    ),
    defaultValues: {
      integration_type: "sns" as const,
      topic_arn: integration?.attributes.configuration.topic_arn || "",
      use_custom_credentials: false,
      enabled: integration?.attributes.enabled ?? true,
      credentials_type: "access-secret-key" as const,
      aws_access_key_id: "",
      aws_secret_access_key: "",
      aws_session_token: "",
      role_arn: "",
      external_id: session?.tenantId || "",
      role_session_name: "",
      session_duration: "",
      show_role_section: false,
    },
  });

  const isLoading = form.formState.isSubmitting;
  const useCustomCredentials = form.watch("use_custom_credentials");

  const buildCredentials = (
    values: z.infer<typeof snsIntegrationFormSchema>,
  ): SNSCredentialsPayload => {
    const credentials: SNSCredentialsPayload = {};

    if (values.role_arn && values.role_arn.trim() !== "") {
      credentials.role_arn = values.role_arn;
      credentials.external_id = values.external_id;

      if (values.role_session_name)
        credentials.role_session_name = values.role_session_name;
      if (values.session_duration)
        credentials.session_duration =
          parseInt(values.session_duration, 10) || 3600;
    }

    if (values.credentials_type === "access-secret-key") {
      credentials.aws_access_key_id = values.aws_access_key_id;
      credentials.aws_secret_access_key = values.aws_secret_access_key;

      if (values.aws_session_token)
        credentials.aws_session_token = values.aws_session_token;
    }

    return credentials;
  };

  const onSubmit = async (values: z.infer<typeof snsIntegrationFormSchema>) => {
    try {
      const formData = new FormData();

      // Add integration type
      formData.append("integration_type", "sns");

      // Configuration (topic ARN)
      if (!isEditingCredentials) {
        const configuration = {
          topic_arn: values.topic_arn,
        };
        formData.append("configuration", JSON.stringify(configuration));
      }

      // Credentials
      if (!isEditingConfig) {
        const credentials: SNSCredentialsPayload =
          useCustomCredentials || isCreating || isEditingCredentials
            ? buildCredentials(values)
            : {};

        if (Object.keys(credentials).length > 0) {
          formData.append("credentials", JSON.stringify(credentials));
        }
      }

      // For creation, we need to provide providers (empty array for SNS)
      if (isCreating) {
        formData.append("providers", JSON.stringify([]));
        formData.append("enabled", JSON.stringify(values.enabled));
      }

      let result;
      if (isEditing) {
        result = await updateIntegration(integration.id, formData);
      } else {
        result = await createIntegration(formData);
      }

      if (result.success && result.data) {
        toast({
          title: isEditing
            ? "SNS Integration Updated"
            : "SNS Integration Created",
          description: isEditing
            ? "Your SNS integration has been updated successfully."
            : "Your SNS integration has been created successfully.",
          variant: "success",
        });
        onSuccess(result.data.id, !isEditing);
      } else {
        toast({
          variant: "destructive",
          title: "Error",
          description: result.error || "Failed to save SNS integration.",
        });
      }
    } catch (error) {
      console.error("SNS Integration form error:", error);
      toast({
        variant: "destructive",
        title: "Error",
        description: "An unexpected error occurred. Please try again.",
      });
    }
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        {/* Configuration Section */}
        {!isEditingCredentials && (
          <div className="space-y-4">
            <div>
              <h3 className="text-base font-semibold">Configuration</h3>
              <p className="text-small text-default-500">
                Configure your Amazon SNS topic for sending email alerts
              </p>
            </div>

            <FormField
              control={form.control}
              name="topic_arn"
              render={({ field }) => (
                <FormControl>
                  <CustomInput
                    label="SNS Topic ARN"
                    labelPlacement="outside"
                    placeholder="arn:aws:sns:us-east-1:123456789012:prowler-alerts"
                    isRequired
                    isDisabled={isEditingCredentials}
                    errorMessage={form.formState.errors.topic_arn?.message}
                    description="The Amazon Resource Name (ARN) of the SNS topic to send alerts to"
                    {...field}
                  />
                </FormControl>
              )}
            />

            {isCreating && (
              <FormField
                control={form.control}
                name="enabled"
                render={({ field }) => (
                  <FormControl>
                    <Checkbox
                      isSelected={field.value}
                      onValueChange={field.onChange}
                    >
                      <span className="text-small">Enable integration</span>
                    </Checkbox>
                  </FormControl>
                )}
              />
            )}
          </div>
        )}

        {/* Credentials Section */}
        {!isEditingConfig && (
          <div className="space-y-4">
            <Divider />

            <div>
              <h3 className="text-base font-semibold">AWS Credentials</h3>
              <p className="text-small text-default-500">
                Configure AWS credentials to access the SNS topic
              </p>
            </div>

            {(isCreating || isEditingCredentials) && (
              <FormField
                control={form.control}
                name="use_custom_credentials"
                render={({ field }) => (
                  <FormControl>
                    <Checkbox
                      isSelected={field.value}
                      onValueChange={field.onChange}
                    >
                      <span className="text-small">
                        Use custom AWS credentials
                      </span>
                    </Checkbox>
                  </FormControl>
                )}
              />
            )}

            {(useCustomCredentials || isEditingCredentials) && (
              <div className="space-y-4">
                <FormField
                  control={form.control}
                  name="credentials_type"
                  render={({ field }) => (
                    <FormControl>
                      <RadioGroup
                        label="Credentials Type"
                        value={field.value}
                        onValueChange={field.onChange}
                      >
                        <Radio value="aws-sdk-default">
                          AWS SDK Default Credentials
                        </Radio>
                        <Radio value="access-secret-key">
                          Access Key & Secret Key
                        </Radio>
                      </RadioGroup>
                    </FormControl>
                  )}
                />

                {form.watch("credentials_type") === "access-secret-key" && (
                  <div className="space-y-4">
                    <FormField
                      control={form.control}
                      name="aws_access_key_id"
                      render={({ field }) => (
                        <FormControl>
                          <CustomInput
                            label="AWS Access Key ID"
                            labelPlacement="outside"
                            placeholder="AKIA..."
                            isRequired
                            errorMessage={
                              form.formState.errors.aws_access_key_id?.message
                            }
                            {...field}
                          />
                        </FormControl>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="aws_secret_access_key"
                      render={({ field }) => (
                        <FormControl>
                          <CustomInput
                            label="AWS Secret Access Key"
                            labelPlacement="outside"
                            type="password"
                            placeholder="Enter secret access key"
                            isRequired
                            errorMessage={
                              form.formState.errors.aws_secret_access_key
                                ?.message
                            }
                            {...field}
                          />
                        </FormControl>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="aws_session_token"
                      render={({ field }) => (
                        <FormControl>
                          <CustomInput
                            label="AWS Session Token (Optional)"
                            labelPlacement="outside"
                            type="password"
                            placeholder="For temporary credentials"
                            errorMessage={
                              form.formState.errors.aws_session_token?.message
                            }
                            {...field}
                          />
                        </FormControl>
                      )}
                    />
                  </div>
                )}

                <Divider />

                <AWSRoleCredentialsForm
                  control={form.control}
                  errors={form.formState.errors}
                  showRoleSection={form.watch("show_role_section") || false}
                  setShowRoleSection={(value) =>
                    form.setValue("show_role_section", value)
                  }
                />
              </div>
            )}

            {!useCustomCredentials && isCreating && (
              <div className="rounded-lg border border-default-200 bg-default-50 p-4">
                <p className="text-small text-default-600">
                  The integration will use the default AWS credentials from the
                  provider configuration. Make sure the provider has access to
                  the SNS topic.
                </p>
              </div>
            )}

            <div className="text-small text-default-500">
              <p className="mb-2">Need help setting up AWS credentials?</p>
              <div className="flex flex-col gap-1">
                {getAWSCredentialsTemplateLinks("sns").map((link) => (
                  <CustomLink
                    key={link.label}
                    href={link.href}
                    isExternal
                    showAnchorIcon
                    size="sm"
                  >
                    {link.label}
                  </CustomLink>
                ))}
              </div>
            </div>
          </div>
        )}

        <FormButtons
          submitLabel={isEditing ? "Update Integration" : "Create Integration"}
          cancelLabel="Cancel"
          isLoading={isLoading}
          onCancel={onCancel}
        />
      </form>
    </Form>
  );
};
