"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";

import { createIntegration, updateIntegration } from "@/actions/integrations";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { Form } from "@/components/ui/form";
import { FormButtons } from "@/components/ui/form/form-buttons";
import {
  type CreateValues,
  editJiraIntegrationFormSchema,
  type FormValues,
  IntegrationProps,
  type JiraCredentialsPayload,
  jiraIntegrationFormSchema,
} from "@/types/integrations";

interface JiraIntegrationFormProps {
  integration?: IntegrationProps | null;
  onSuccess: (integrationId?: string, shouldTestConnection?: boolean) => void;
  onCancel: () => void;
}

export const JiraIntegrationForm = ({
  integration,
  onSuccess,
  onCancel,
}: JiraIntegrationFormProps) => {
  const { toast } = useToast();
  const isEditing = !!integration;
  const isCreating = !isEditing;

  const form = useForm<FormValues>({
    resolver: zodResolver(
      isCreating ? jiraIntegrationFormSchema : editJiraIntegrationFormSchema,
    ),
    defaultValues: {
      integration_type: "jira" as const,
      domain: integration?.attributes.configuration.domain || "",
      enabled: integration?.attributes.enabled ?? true,
      user_mail: "",
      api_token: "",
    },
  });

  const isLoading = form.formState.isSubmitting;

  const normalizeDomain = (raw: string): string => {
    let v = (raw || "").trim().toLowerCase();
    // strip protocol
    v = v.replace(/^https?:\/\//, "");
    // take hostname (drop path/query)
    v = v.split("/")[0];
    // if full host provided, strip Atlassian suffix to keep site name only
    if (v.endsWith(".atlassian.net")) {
      v = v.replace(/\.atlassian\.net$/, "");
    }
    return v;
  };

  const onSubmit = async (data: FormValues) => {
    try {
      const formData = new FormData();

      // Add integration type
      formData.append("integration_type", "jira");

      // Prepare credentials object
      const credentials: JiraCredentialsPayload = {};

      // For editing, only add fields that have values
      if (isEditing) {
        // Only add domain if it's provided (for updates, domain might not be editable)
        if (data.domain) credentials.domain = normalizeDomain(data.domain);
        if (data.user_mail) credentials.user_mail = data.user_mail;
        if (data.api_token) credentials.api_token = data.api_token;
      } else {
        // For creation, all credential fields are required
        const createData = data as CreateValues;
        credentials.domain = normalizeDomain(createData.domain);
        credentials.user_mail = createData.user_mail;
        credentials.api_token = createData.api_token;
      }

      // Add credentials as JSON
      if (Object.keys(credentials).length > 0) {
        formData.append("credentials", JSON.stringify(credentials));
      }

      // For creation, we need to provide configuration and providers
      if (isCreating) {
        formData.append("configuration", JSON.stringify({}));
        formData.append("providers", JSON.stringify([]));
        // enabled exists only in create schema
        formData.append(
          "enabled",
          JSON.stringify((data as CreateValues).enabled),
        );
      }

      type IntegrationResult =
        | { success: string; integrationId?: string }
        | { error: string };
      let result: IntegrationResult;
      if (isEditing) {
        result = await updateIntegration(integration.id, formData);
      } else {
        result = await createIntegration(formData);
      }

      if (result && "success" in result && result.success) {
        toast({
          title: "Success!",
          description: `Jira integration ${isEditing ? "updated" : "created"} successfully.`,
        });

        // Always test connection when creating or updating
        const shouldTestConnection = true;
        const integrationId =
          "integrationId" in result ? result.integrationId : integration?.id;

        onSuccess(integrationId, shouldTestConnection);
      } else if (result && "error" in result) {
        toast({
          variant: "destructive",
          title: "Operation Failed",
          description: result.error,
        });
      }
    } catch (_error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: `Failed to ${isEditing ? "update" : "create"} Jira integration. Please try again.`,
      });
    }
  };

  const renderForm = () => {
    return (
      <>
        {isCreating && (
          <CustomInput
            control={form.control}
            name="domain"
            type="text"
            label="Jira Domain"
            labelPlacement="inside"
            placeholder="your-domain.atlassian.net"
            isRequired
            isDisabled={isLoading}
          />
        )}

        {isEditing && integration?.attributes.configuration.domain && (
          <CustomInput
            control={form.control}
            name="domain"
            type="text"
            label="Jira Domain"
            labelPlacement="inside"
            placeholder="your-domain.atlassian.net"
            isDisabled={isLoading}
          />
        )}

        <CustomInput
          control={form.control}
          name="user_mail"
          type="email"
          label="User Email"
          labelPlacement="inside"
          placeholder="user@example.com"
          isRequired
          isDisabled={isLoading}
        />

        <CustomInput
          control={form.control}
          name="api_token"
          type="password"
          label="API Token"
          labelPlacement="inside"
          placeholder="Enter your Jira API token"
          isRequired
          isDisabled={isLoading}
        />

        <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 dark:border-blue-800 dark:bg-blue-900/20">
          <p className="text-sm text-blue-800 dark:text-blue-200">
            To generate an API token with scopes, visit your{" "}
            <a
              href="https://id.atlassian.com/manage-profile/security/api-tokens"
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium underline"
            >
              Atlassian account settings
            </a>
            .
          </p>
        </div>
      </>
    );
  };

  const getButtonLabel = () => {
    if (isEditing) {
      return "Update Credentials";
    }
    return "Create Integration";
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className="flex flex-col gap-6"
      >
        <div className="flex flex-col gap-4">
          <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
            <p className="text-default-500 flex items-center gap-2 text-sm">
              Need help configuring your Jira integration?
            </p>
            <CustomLink
              href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-jira-integration/"
              target="_blank"
              size="sm"
            >
              Read the docs
            </CustomLink>
          </div>
          {renderForm()}
        </div>
        <FormButtons
          setIsOpen={() => {}}
          onCancel={onCancel}
          submitText={getButtonLabel()}
          cancelText="Cancel"
          loadingText="Processing..."
          isDisabled={isLoading}
        />
      </form>
    </Form>
  );
};
