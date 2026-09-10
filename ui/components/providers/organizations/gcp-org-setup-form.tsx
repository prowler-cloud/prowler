"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import type { FormEvent } from "react";
import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { updateOrganizationName } from "@/actions/organizations/organizations";
import { GCPProviderBadge } from "@/components/icons/providers-badge";
import { RadioCard } from "@/components/providers/radio-card";
import type { WizardFooterConfig } from "@/components/providers/wizard/steps/footer-controls";
import { WIZARD_FOOTER_ACTION_TYPE } from "@/components/providers/wizard/steps/footer-controls";
import type { OrgWizardIntent } from "@/components/providers/wizard/types";
import { ORG_WIZARD_INTENT } from "@/components/providers/wizard/types";
import {
  WizardInputField,
  WizardTextareaField,
} from "@/components/providers/workflow/forms/fields";
import { useToast } from "@/components/shadcn";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { Form } from "@/components/shadcn/form";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { organizationNameFallbackHint } from "@/lib/organizations";
import { useOrgSetupStore } from "@/store/organizations/store";
import type { OrgSetupPhase } from "@/types/organizations";
import {
  ORG_SECRET_TYPE,
  ORG_SETUP_PHASE,
  ORGANIZATION_TYPE,
} from "@/types/organizations";

import { DiscoveryTimeoutNotice } from "./discovery-timeout-notice";
import { useOrgSetupSubmission } from "./hooks/use-org-setup-submission";
import { SecretReplaceWarningModal } from "./secret-replace-warning-modal";

const GCP_ORG_ID_PATTERN = /^[0-9]+$/;

function isJsonObject(value: string): boolean {
  try {
    const parsed = JSON.parse(value);
    return (
      typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
    );
  } catch {
    return false;
  }
}

const gcpOrgSetupSchema = z
  .object({
    organizationName: z.string().trim().optional(),
    gcpOrgId: z
      .string()
      .trim()
      .min(1, "Organization ID is required")
      .regex(
        GCP_ORG_ID_PATTERN,
        "Must be a numeric Google Cloud organization ID (e.g., 123456789012)",
      ),
    credentialMethod: z.enum([
      ORG_SECRET_TYPE.SERVICE_ACCOUNT,
      ORG_SECRET_TYPE.STATIC,
    ]),
    serviceAccountKey: z.string().optional(),
    clientId: z.string().optional(),
    clientSecret: z.string().optional(),
    refreshToken: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    if (data.credentialMethod === ORG_SECRET_TYPE.SERVICE_ACCOUNT) {
      if (!data.serviceAccountKey || !isJsonObject(data.serviceAccountKey)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Invalid JSON format. Please provide a valid JSON object.",
          path: ["serviceAccountKey"],
        });
      }
      return;
    }

    for (const [field, label] of [
      ["clientId", "Client ID"],
      ["clientSecret", "Client Secret"],
      ["refreshToken", "Refresh Token"],
    ] as const) {
      if (!data[field]?.trim()) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${label} is required`,
          path: [field],
        });
      }
    }
  });

type GcpOrgSetupFormData = z.infer<typeof gcpOrgSetupSchema>;

interface GcpOrgSetupFormInitialValues {
  organizationName: string;
  gcpOrgId: string;
}

interface GcpOrgSetupFormProps {
  onBack: () => void;
  onClose?: () => void;
  onNext: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
  onPhaseChange: (phase: OrgSetupPhase) => void;
  initialPhase?: OrgSetupPhase;
  initialValues?: GcpOrgSetupFormInitialValues;
  intent?: OrgWizardIntent;
}

export function GcpOrgSetupForm({
  onBack,
  onClose,
  onNext,
  onFooterChange,
  onPhaseChange,
  initialPhase = ORG_SETUP_PHASE.DETAILS,
  initialValues,
  intent = ORG_WIZARD_INTENT.FULL,
}: GcpOrgSetupFormProps) {
  const { organizationId } = useOrgSetupStore();
  const { toast } = useToast();
  const [setupPhase, setSetupPhase] = useState<OrgSetupPhase>(initialPhase);
  const [isSaving, setIsSaving] = useState(false);
  const formId = "gcp-org-wizard-setup-form";
  const formRef = useRef<HTMLFormElement>(null);

  const isReadOnlyOrgId = Boolean(initialValues?.gcpOrgId);

  const form = useForm<GcpOrgSetupFormData>({
    resolver: zodResolver(gcpOrgSetupSchema),
    mode: "onChange",
    reValidateMode: "onChange",
    defaultValues: {
      organizationName: initialValues?.organizationName ?? "",
      gcpOrgId: initialValues?.gcpOrgId ?? "",
      credentialMethod: ORG_SECRET_TYPE.SERVICE_ACCOUNT,
      serviceAccountKey: "",
      clientId: "",
      clientSecret: "",
      refreshToken: "",
    },
  });
  const {
    control,
    handleSubmit,
    formState: { isSubmitting, isValid },
    setError,
    setValue,
    watch,
  } = form;

  const gcpOrgId = watch("gcpOrgId") || "";
  const isOrgIdValid = GCP_ORG_ID_PATTERN.test(gcpOrgId.trim());
  const credentialMethod = watch("credentialMethod");

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
    // Unlike an AWS role secret, a GCP secret echoes no external id.
    stackSetExternalId: "",
    onNext,
    // Only the fields this form renders: a `setError` on an unregistered field
    // would render nowhere, so anything else goes back for the hook to banner.
    setFieldError: (field, message) => {
      switch (field) {
        case "organizationName":
        case "gcpOrgId":
        case "serviceAccountKey":
        case "clientId":
        case "clientSecret":
        case "refreshToken":
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
        actionDisabled: isEditName ? isSaving : !isOrgIdValid,
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
    isOrgIdValid,
    isSaving,
    isValid,
    onBack,
    onFooterChange,
    setupPhase,
  ]);

  const handleContinueToAccess = () => {
    setApiError(null);

    if (!isOrgIdValid) {
      setError("gcpOrgId", {
        message: gcpOrgId.trim()
          ? "Must be a numeric Google Cloud organization ID (e.g., 123456789012)"
          : "Organization ID is required",
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
      submitOrganizationSetup({ ...data, orgType: ORGANIZATION_TYPE.GCP }),
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
              <GCPProviderBadge size={32} />
              <h3 className="text-base font-semibold">
                Google Cloud (GCP) / Organization Details
              </h3>
            </div>

            <p className="text-muted-foreground text-sm">
              Enter the Google Cloud organization ID for the projects you want
              to add to Prowler.
            </p>
          </div>
        )}

        {setupPhase === ORG_SETUP_PHASE.ACCESS && (
          <div className="flex items-center gap-4">
            <GCPProviderBadge size={32} />
            <h3 className="text-base font-semibold">
              Google Cloud (GCP) / Authentication Details
            </h3>
          </div>
        )}

        {setupPhase === ORG_SETUP_PHASE.ACCESS && isBusy && (
          <div className="flex min-h-[220px] items-center justify-center">
            <div className="flex items-center gap-3 py-2">
              <Spinner className="size-6" />
              <p className="text-sm font-medium">Gathering GCP Projects...</p>
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
              name="gcpOrgId"
              label="Organization ID"
              labelPlacement="outside"
              placeholder="e.g. 123456789012"
              isRequired
              isReadOnly={isReadOnlyOrgId}
              isDisabled={isReadOnlyOrgId}
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
              {organizationNameFallbackHint(ORGANIZATION_TYPE.GCP)}
            </p>
          </div>
        )}

        {setupPhase === ORG_SETUP_PHASE.ACCESS && !isBusy && (
          <div className="flex flex-col gap-6">
            <p className="text-text-neutral-primary text-sm leading-7 font-normal">
              Choose how Prowler authenticates to your Google Cloud
              organization.
            </p>

            <div className="flex flex-col gap-3">
              <RadioCard
                title="Service Account Key"
                icon={GCPProviderBadge}
                selected={credentialMethod === ORG_SECRET_TYPE.SERVICE_ACCOUNT}
                onClick={() =>
                  setValue(
                    "credentialMethod",
                    ORG_SECRET_TYPE.SERVICE_ACCOUNT,
                    {
                      shouldValidate: true,
                    },
                  )
                }
              />
              <RadioCard
                title="Client ID, Client Secret and Refresh Token"
                icon={GCPProviderBadge}
                selected={credentialMethod === ORG_SECRET_TYPE.STATIC}
                onClick={() =>
                  setValue("credentialMethod", ORG_SECRET_TYPE.STATIC, {
                    shouldValidate: true,
                  })
                }
              />
            </div>

            {credentialMethod === ORG_SECRET_TYPE.SERVICE_ACCOUNT ? (
              <WizardTextareaField
                control={control}
                name="serviceAccountKey"
                label="Service Account Key"
                labelPlacement="outside"
                placeholder="Paste your Service Account Key JSON content here"
                minRows={10}
                isRequired
              />
            ) : (
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
                <WizardInputField
                  control={control}
                  name="refreshToken"
                  label="Refresh Token"
                  labelPlacement="outside"
                  type="password"
                  isRequired
                />
              </div>
            )}
          </div>
        )}
      </form>
    </Form>
  );
}
