"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import type { FormEvent } from "react";
import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { updateOrganizationName } from "@/actions/organizations/organizations";
import { AzureProviderBadge } from "@/components/icons/providers-badge";
import type { WizardFooterConfig } from "@/components/providers/wizard/steps/footer-controls";
import { WIZARD_FOOTER_ACTION_TYPE } from "@/components/providers/wizard/steps/footer-controls";
import type { OrgWizardIntent } from "@/components/providers/wizard/types";
import { ORG_WIZARD_INTENT } from "@/components/providers/wizard/types";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { useToast } from "@/components/shadcn";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { Form } from "@/components/shadcn/form";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { useOrgSetupStore } from "@/store/organizations/store";
import type { OrgSetupPhase } from "@/types/organizations";
import { ORG_SETUP_PHASE, ORGANIZATION_TYPE } from "@/types/organizations";

import { DiscoveryTimeoutNotice } from "./discovery-timeout-notice";
import { useOrgSetupSubmission } from "./hooks/use-org-setup-submission";
import { SecretReplaceWarningModal } from "./secret-replace-warning-modal";

const TENANT_ID_INVALID =
  "Must be a valid Microsoft Entra tenant ID (e.g., 11111111-1111-4111-8111-111111111111)";

const azureOrgSetupSchema = z.object({
  organizationName: z.string().trim().optional(),
  // Onboarding always covers the tenant root Management Group, which the API
  // derives from the tenant ID — so the tenant is the only identifier collected.
  tenantId: z
    .string()
    .trim()
    .min(1, "Tenant ID is required")
    .pipe(z.uuid(TENANT_ID_INVALID)),
  clientId: z
    .string()
    .trim()
    .min(1, "Client ID is required")
    .pipe(z.uuid("Must be a valid service principal client ID (UUID)")),
  clientSecret: z.string().trim().min(1, "Client Secret is required"),
});

type AzureOrgSetupFormData = z.infer<typeof azureOrgSetupSchema>;

interface AzureOrgSetupFormInitialValues {
  organizationName: string;
  tenantId: string;
}

interface AzureOrgSetupFormProps {
  onBack: () => void;
  onClose?: () => void;
  onNext: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
  onPhaseChange: (phase: OrgSetupPhase) => void;
  initialPhase?: OrgSetupPhase;
  initialValues?: AzureOrgSetupFormInitialValues;
  intent?: OrgWizardIntent;
}

export function AzureOrgSetupForm({
  onBack,
  onClose,
  onNext,
  onFooterChange,
  onPhaseChange,
  initialPhase = ORG_SETUP_PHASE.DETAILS,
  initialValues,
  intent = ORG_WIZARD_INTENT.FULL,
}: AzureOrgSetupFormProps) {
  const { organizationId } = useOrgSetupStore();
  const { toast } = useToast();
  const [setupPhase, setSetupPhase] = useState<OrgSetupPhase>(initialPhase);
  const [isSaving, setIsSaving] = useState(false);
  const formId = "azure-org-wizard-setup-form";
  const formRef = useRef<HTMLFormElement>(null);

  const isReadOnlyTenantId = Boolean(initialValues?.tenantId);

  const form = useForm<AzureOrgSetupFormData>({
    resolver: zodResolver(azureOrgSetupSchema),
    mode: "onChange",
    reValidateMode: "onChange",
    defaultValues: {
      organizationName: initialValues?.organizationName ?? "",
      tenantId: initialValues?.tenantId ?? "",
      clientId: "",
      clientSecret: "",
    },
  });
  const {
    control,
    handleSubmit,
    formState: { isSubmitting, isValid },
    setError,
    watch,
  } = form;

  const tenantId = watch("tenantId") || "";
  const isTenantIdValid = z.uuid().safeParse(tenantId.trim()).success;

  const {
    apiError,
    setApiError,
    submitOrganizationSetup,
    replaceSecretWarning,
    confirmSecretReplace,
    cancelSecretReplace,
    discoveryTimedOut,
    discoveryFailed,
    isSubmissionPending,
    keepWaitingForDiscovery,
    retryDiscovery,
  } = useOrgSetupSubmission({
    // Unlike an AWS role secret, a service principal secret echoes no external id.
    stackSetExternalId: "",
    onNext,
    // Only the fields this form renders: a `setError` on an unregistered field
    // would render nowhere, so anything else goes back for the hook to banner.
    setFieldError: (field, message) => {
      switch (field) {
        case "organizationName":
        case "tenantId":
        case "clientId":
        case "clientSecret":
          setError(field, { message });
          return true;
        default:
          return false;
      }
    },
  });

  // `isSubmitting` only covers a submit react-hook-form started itself, not the
  // chain re-entered by confirming a replacement, keeping waiting or retrying.
  const isBusy = isSubmitting || isSubmissionPending;

  useEffect(() => {
    onPhaseChange(setupPhase);
  }, [onPhaseChange, setupPhase]);

  useEffect(() => {
    if (setupPhase === ORG_SETUP_PHASE.DETAILS) {
      const isEditName = intent === ORG_WIZARD_INTENT.EDIT_NAME;
      onFooterChange({
        showBack: true,
        backLabel: "Back",
        onBack,
        showAction: true,
        actionLabel: isEditName ? "Save" : "Next",
        actionDisabled: isEditName ? isSaving : !isTenantIdValid,
        actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
        actionFormId: formId,
      });
      return;
    }

    const isEditCredentials = intent === ORG_WIZARD_INTENT.EDIT_CREDENTIALS;
    onFooterChange({
      showBack: !isEditCredentials,
      backLabel: "Back",
      backDisabled: isBusy,
      onBack: () => setSetupPhase(ORG_SETUP_PHASE.DETAILS),
      showAction: true,
      actionLabel: "Authenticate",
      actionDisabled: isBusy || !isValid,
      actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: formId,
    });
  }, [
    formId,
    intent,
    isBusy,
    isSaving,
    isTenantIdValid,
    isValid,
    onBack,
    onFooterChange,
    setupPhase,
  ]);

  const handleContinueToAccess = () => {
    setApiError(null);

    if (!isTenantIdValid) {
      setError("tenantId", {
        message: tenantId.trim() ? TENANT_ID_INVALID : "Tenant ID is required",
      });
      return;
    }

    setSetupPhase(ORG_SETUP_PHASE.ACCESS);
  };

  const handleSaveNameOnly = async () => {
    if (!organizationId) return;
    setIsSaving(true);
    const name = form.getValues("organizationName")?.trim() || "";

    const result = await updateOrganizationName(organizationId, name);

    setIsSaving(false);

    if (result?.error || result?.errors) {
      const errorMsg =
        result.errors?.[0]?.detail ?? result.error ?? "Failed to update name";
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: errorMsg,
      });
      return;
    }

    toast({
      title: "Success!",
      description: "Organization name updated successfully.",
    });
    onClose?.();
  };

  const handleFormSubmit = (event: FormEvent<HTMLFormElement>) => {
    if (setupPhase === ORG_SETUP_PHASE.DETAILS) {
      event.preventDefault();

      if (intent === ORG_WIZARD_INTENT.EDIT_NAME) {
        void handleSaveNameOnly();
        return;
      }

      handleContinueToAccess();
      return;
    }

    void handleSubmit((data) =>
      submitOrganizationSetup({ ...data, orgType: ORGANIZATION_TYPE.AZURE }),
    )(event);
  };

  useEffect(() => {
    if (!apiError) return;
    formRef.current?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [apiError]);

  return (
    <Form {...form}>
      <SecretReplaceWarningModal
        warning={replaceSecretWarning}
        onConfirm={confirmSecretReplace}
        onCancel={cancelSecretReplace}
      />
      <form
        id={formId}
        ref={formRef}
        onSubmit={handleFormSubmit}
        className="flex flex-col gap-5"
      >
        {setupPhase === ORG_SETUP_PHASE.DETAILS && (
          <div className="flex flex-col gap-6">
            <div className="flex items-center gap-4">
              <AzureProviderBadge size={32} />
              <h3 className="text-base font-semibold">
                Microsoft Azure / Organization Details
              </h3>
            </div>

            <p className="text-muted-foreground text-sm">
              Enter the Microsoft Entra tenant ID for the subscriptions you want
              to add to Prowler.
            </p>
          </div>
        )}

        {setupPhase === ORG_SETUP_PHASE.ACCESS && (
          <div className="flex items-center gap-4">
            <AzureProviderBadge size={32} />
            <h3 className="text-base font-semibold">
              Microsoft Azure / Authentication Details
            </h3>
          </div>
        )}

        {setupPhase === ORG_SETUP_PHASE.ACCESS && isBusy && (
          <div className="flex min-h-[220px] items-center justify-center">
            <div className="flex items-center gap-3 py-2">
              <Spinner className="size-6" />
              <p className="text-sm font-medium">
                Gathering Azure Subscriptions...
              </p>
            </div>
          </div>
        )}

        {apiError && (
          <Alert variant="error">
            <AlertDescription className="text-text-error-primary">
              {apiError}
            </AlertDescription>
          </Alert>
        )}

        {setupPhase === ORG_SETUP_PHASE.ACCESS &&
          discoveryTimedOut &&
          !isBusy && (
            <DiscoveryTimeoutNotice
              onKeepWaiting={() => void keepWaitingForDiscovery()}
              onRetry={() => void retryDiscovery()}
            />
          )}

        {setupPhase === ORG_SETUP_PHASE.ACCESS &&
          discoveryFailed &&
          !isBusy && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="self-start"
              onClick={() => void retryDiscovery()}
            >
              Retry discovery
            </Button>
          )}

        {setupPhase === ORG_SETUP_PHASE.DETAILS && (
          <div className="flex flex-col gap-4">
            <WizardInputField
              control={control}
              name="tenantId"
              label="Tenant ID"
              labelPlacement="outside"
              placeholder="e.g. 11111111-1111-4111-8111-111111111111"
              isRequired
              isReadOnly={isReadOnlyTenantId}
              isDisabled={isReadOnlyTenantId}
            />

            <WizardInputField
              control={control}
              name="organizationName"
              label="Name (optional)"
              labelPlacement="outside"
              placeholder=""
              isRequired={false}
            />

            <p className="text-muted-foreground text-sm">
              If left blank, Prowler will use the organization name stored in
              Azure.
            </p>
          </div>
        )}

        {setupPhase === ORG_SETUP_PHASE.ACCESS && !isBusy && (
          <div className="flex flex-col gap-6">
            <p className="text-text-neutral-primary text-sm leading-7 font-normal">
              Enter the service principal Prowler authenticates with. It needs
              the Reader role on the tenant root Management Group.
            </p>

            <div className="flex flex-col gap-4">
              <WizardInputField
                control={control}
                name="clientId"
                label="Client ID"
                labelPlacement="outside"
                isRequired
              />
              <WizardInputField
                control={control}
                name="clientSecret"
                label="Client Secret"
                labelPlacement="outside"
                type="password"
                isRequired
              />
            </div>
          </div>
        )}
      </form>
    </Form>
  );
}
