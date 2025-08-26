"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Checkbox, Divider, Radio, RadioGroup } from "@nextui-org/react";
import { ArrowLeftIcon, ArrowRightIcon } from "lucide-react";
import { useSession } from "next-auth/react";
import { useEffect, useMemo, useState } from "react";
import { Control, useForm } from "react-hook-form";

import { createIntegration, updateIntegration } from "@/actions/integrations";
import { EnhancedProviderSelector } from "@/components/providers/enhanced-provider-selector";
import { AWSRoleCredentialsForm } from "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-role-credentials-form";
import { useToast } from "@/components/ui";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { Form, FormControl, FormField } from "@/components/ui/form";
import { FormButtons } from "@/components/ui/form/form-buttons";
import { getAWSCredentialsTemplateLinks } from "@/lib";
import { AWSCredentialsRole } from "@/types";
import {
  editSecurityHubIntegrationFormSchema,
  IntegrationProps,
  securityHubIntegrationFormSchema,
} from "@/types/integrations";
import { ProviderProps } from "@/types/providers";

interface SecurityHubIntegrationFormProps {
  integration?: IntegrationProps | null;
  providers: ProviderProps[];
  existingIntegrations?: IntegrationProps[];
  onSuccess: (integrationId?: string, shouldTestConnection?: boolean) => void;
  onCancel: () => void;
  editMode?: "configuration" | "credentials" | null;
}

export const SecurityHubIntegrationForm = ({
  integration,
  providers,
  existingIntegrations = [],
  onSuccess,
  onCancel,
  editMode = null,
}: SecurityHubIntegrationFormProps) => {
  const { data: session } = useSession();
  const { toast } = useToast();
  const [currentStep, setCurrentStep] = useState(
    editMode === "credentials" ? 1 : 0,
  );
  const isEditing = !!integration;
  const isCreating = !isEditing;
  const isEditingConfig = editMode === "configuration";
  const isEditingCredentials = editMode === "credentials";

  const disabledProviderIds = useMemo(() => {
    // When editing, no providers should be disabled since we're not changing it
    if (isEditing) {
      return [];
    }

    // When creating, disable providers that are already used by other Security Hub integrations
    const usedProviderIds: string[] = [];
    existingIntegrations.forEach((existingIntegration) => {
      const providerRelationships =
        existingIntegration.relationships?.providers?.data;
      if (providerRelationships && providerRelationships.length > 0) {
        usedProviderIds.push(providerRelationships[0].id);
      }
    });

    return usedProviderIds;
  }, [isEditing, existingIntegrations]);

  const form = useForm({
    resolver: zodResolver(
      isEditingCredentials || isCreating
        ? securityHubIntegrationFormSchema
        : editSecurityHubIntegrationFormSchema,
    ),
    defaultValues: {
      integration_type: "aws_security_hub" as const,
      provider_id: integration?.relationships?.providers?.data?.[0]?.id || "",
      send_only_fails:
        integration?.attributes.configuration.send_only_fails ?? true,
      archive_previous_findings:
        integration?.attributes.configuration.archive_previous_findings ??
        false,
      use_custom_credentials: false,
      enabled: integration?.attributes.enabled ?? true,
      credentials_type: "access-secret-key" as const,
      aws_access_key_id: "",
      aws_secret_access_key: "",
      aws_session_token: "",
      role_arn: isEditingCredentials
        ? ""
        : integration?.attributes.configuration.credentials?.role_arn || "",
      external_id:
        integration?.attributes.configuration.credentials?.external_id ||
        session?.tenantId ||
        "",
      role_session_name: "",
      session_duration: "",
    },
  });

  const isLoading = form.formState.isSubmitting;
  const useCustomCredentials = form.watch("use_custom_credentials");
  const providerIdValue = form.watch("provider_id");
  const hasErrors = !!form.formState.errors.provider_id || !providerIdValue;

  useEffect(() => {
    if (!useCustomCredentials && isCreating) {
      setCurrentStep(0);
    }
  }, [useCustomCredentials, isCreating]);

  const handleNext = async (e: React.FormEvent) => {
    e.preventDefault();

    if (isEditingConfig || isEditingCredentials) {
      return;
    }

    const stepFields = currentStep === 0 ? (["provider_id"] as const) : [];
    const isValid = stepFields.length === 0 || (await form.trigger(stepFields));

    if (isValid) {
      setCurrentStep(1);
    }
  };

  const handleBack = () => {
    setCurrentStep(0);
  };

  const buildCredentials = (values: any) => {
    const credentials: any = {};

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

  const buildConfiguration = (values: any) => {
    const configuration: any = {};

    configuration.send_only_fails = values.send_only_fails ?? true;
    configuration.archive_previous_findings =
      values.archive_previous_findings ?? false;

    return configuration;
  };

  const buildFormData = (values: any) => {
    const formData = new FormData();
    formData.append("integration_type", values.integration_type);

    if (isEditingConfig) {
      const configuration = buildConfiguration(values);
      if (Object.keys(configuration).length > 0) {
        formData.append("configuration", JSON.stringify(configuration));
      }
    } else if (isEditingCredentials) {
      // When editing credentials, check if using custom credentials
      if (!values.use_custom_credentials) {
        // Use provider credentials - send empty object
        formData.append("credentials", JSON.stringify({}));
      } else {
        // Use custom credentials
        const credentials = buildCredentials(values);
        formData.append("credentials", JSON.stringify(credentials));
      }
    } else {
      const configuration = buildConfiguration(values);
      formData.append("configuration", JSON.stringify(configuration));

      if (values.use_custom_credentials) {
        const credentials = buildCredentials(values);
        formData.append("credentials", JSON.stringify(credentials));
      } else {
        formData.append("credentials", JSON.stringify({}));
      }

      formData.append("enabled", JSON.stringify(values.enabled ?? true));

      // Send provider_id as an array for consistency with the action
      formData.append("providers", JSON.stringify([values.provider_id]));
    }

    return formData;
  };

  const onSubmit = async (values: any) => {
    const formData = buildFormData(values);

    try {
      let result;
      let shouldTestConnection = false;

      if (isEditing && integration) {
        result = await updateIntegration(integration.id, formData);
        // Test connection ONLY if we're editing credentials (Security Hub doesn't need test for config changes)
        shouldTestConnection = isEditingCredentials;
      } else {
        result = await createIntegration(formData);
        // Always test connection for new integrations
        shouldTestConnection = true;
      }

      if ("success" in result) {
        toast({
          title: "Success!",
          description: `Security Hub integration ${isEditing ? "updated" : "created"} successfully.`,
        });

        // Pass the integration ID and whether to test connection to the success callback
        onSuccess(result.integrationId, shouldTestConnection);
      } else if ("error" in result) {
        const errorMessage = result.error;

        toast({
          variant: "destructive",
          title: "Security Hub Integration Error",
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
    if (isEditingCredentials) {
      // When editing credentials, show the credential type selector first
      return (
        <div className="space-y-4">
          <RadioGroup
            size="sm"
            aria-label="Credential type"
            value={useCustomCredentials ? "custom" : "provider"}
            onValueChange={(value) => {
              form.setValue("use_custom_credentials", value === "custom", {
                shouldValidate: true,
                shouldDirty: true,
              });
            }}
          >
            <Radio value="provider">
              <span className="text-sm">Use provider credentials</span>
            </Radio>
            <Radio value="custom">
              <span className="text-sm">Use custom credentials</span>
            </Radio>
          </RadioGroup>

          {useCustomCredentials && (
            <>
              <Divider />
              <AWSRoleCredentialsForm
                control={form.control as unknown as Control<AWSCredentialsRole>}
                setValue={form.setValue as any}
                externalId={
                  form.getValues("external_id") || session?.tenantId || ""
                }
                templateLinks={getAWSCredentialsTemplateLinks(
                  form.getValues("external_id") || session?.tenantId || "",
                  "SecurityHub",
                )}
                type="integrations"
              />
            </>
          )}
        </div>
      );
    }

    if (currentStep === 1 && useCustomCredentials) {
      const externalId =
        form.getValues("external_id") || session?.tenantId || "";
      const templateLinks = getAWSCredentialsTemplateLinks(
        externalId,
        "SecurityHub",
      );

      return (
        <AWSRoleCredentialsForm
          control={form.control as unknown as Control<AWSCredentialsRole>}
          setValue={form.setValue as any}
          externalId={externalId}
          templateLinks={templateLinks}
          type="integrations"
        />
      );
    }

    if (isEditingConfig || currentStep === 0) {
      return (
        <>
          {!isEditingConfig && (
            <>
              <div className="space-y-4">
                <EnhancedProviderSelector
                  control={form.control}
                  name="provider_id"
                  providers={providers}
                  label="AWS Provider"
                  placeholder="Search and select an AWS provider"
                  isInvalid={!!form.formState.errors.provider_id}
                  selectionMode="single"
                  providerType="aws"
                  enableSearch={true}
                  disabledProviderIds={disabledProviderIds}
                />
              </div>
              <Divider />
            </>
          )}

          <div className="flex flex-col gap-3">
            <FormField
              control={form.control}
              name="send_only_fails"
              render={({ field }) => (
                <FormControl>
                  <Checkbox
                    isSelected={field.value}
                    onValueChange={field.onChange}
                    size="sm"
                  >
                    <span className="text-sm">Send only Failed Findings</span>
                  </Checkbox>
                </FormControl>
              )}
            />

            <FormField
              control={form.control}
              name="archive_previous_findings"
              render={({ field }) => (
                <FormControl>
                  <Checkbox
                    isSelected={field.value}
                    onValueChange={field.onChange}
                    size="sm"
                  >
                    <span className="text-sm">Archive previous findings</span>
                  </Checkbox>
                </FormControl>
              )}
            />

            {isCreating && (
              <FormField
                control={form.control}
                name="use_custom_credentials"
                render={({ field }) => (
                  <FormControl>
                    <Checkbox
                      isSelected={field.value}
                      onValueChange={field.onChange}
                      size="sm"
                    >
                      <span className="text-sm">Use custom credentials</span>
                    </Checkbox>
                  </FormControl>
                )}
              />
            )}
          </div>
        </>
      );
    }

    return null;
  };

  const renderStepButtons = () => {
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

    if (currentStep === 0 && !useCustomCredentials) {
      return (
        <FormButtons
          setIsOpen={() => {}}
          onCancel={onCancel}
          submitText="Create Integration"
          cancelText="Cancel"
          loadingText="Creating..."
          isDisabled={isLoading || hasErrors}
        />
      );
    }

    if (currentStep === 0 && useCustomCredentials) {
      return (
        <FormButtons
          setIsOpen={() => {}}
          onCancel={onCancel}
          submitText="Next"
          cancelText="Cancel"
          loadingText="Processing..."
          isDisabled={isLoading || hasErrors}
          rightIcon={<ArrowRightIcon size={24} />}
        />
      );
    }

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
          isEditingConfig ||
          isEditingCredentials ||
          (currentStep === 0 && !useCustomCredentials)
            ? form.handleSubmit(onSubmit)
            : currentStep === 0
              ? handleNext
              : form.handleSubmit(onSubmit)
        }
        className="flex flex-col space-y-6"
      >
        <div className="flex flex-col space-y-4">
          <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
            <p className="flex items-center gap-2 text-sm text-default-500">
              Need help configuring your AWS Security Hub integration?
            </p>
            <CustomLink
              href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/securityhub/"
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
