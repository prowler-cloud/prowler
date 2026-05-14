"use client";

import { useClipboard } from "@heroui/use-clipboard";
import { zodResolver } from "@hookform/resolvers/zod";
import { Check, Copy, ExternalLink } from "lucide-react";
import { useSession } from "next-auth/react";
import { FormEvent, useEffect, useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { z } from "zod";

import { updateOrganizationName } from "@/actions/organizations/organizations";
import { AWSProviderBadge } from "@/components/icons/providers-badge";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import {
  ORG_WIZARD_INTENT,
  OrgWizardIntent,
} from "@/components/providers/wizard/types";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { useToast } from "@/components/ui";
import { Form } from "@/components/ui/form";
import {
  getAWSCredentialsTemplateLinks,
  PROWLER_CF_TEMPLATE_URL,
  STACKSET_CONSOLE_URL,
} from "@/lib";
import { useOrgSetupStore } from "@/store/organizations/store";
import { ORG_SETUP_PHASE, OrgSetupPhase } from "@/types/organizations";

import { useOrgSetupSubmission } from "./hooks/use-org-setup-submission";

const orgSetupSchema = z.object({
  organizationName: z.string().trim().optional(),
  awsOrgId: z
    .string()
    .trim()
    .min(1, "Organization ID is required")
    .regex(
      /^o-[a-z0-9]{10,32}$/,
      "Must be a valid AWS Organization ID (e.g., o-abc123def4)",
    ),
  roleArn: z
    .string()
    .trim()
    .min(1, "Role ARN is required")
    .regex(
      /^arn:aws:iam::\d{12}:role\//,
      "Must be a valid IAM Role ARN (e.g., arn:aws:iam::123456789012:role/ProwlerScan)",
    ),
  stackSetDeployed: z.boolean().refine((value) => value, {
    message: "You must confirm the StackSet deployment before continuing.",
  }),
});

type OrgSetupFormData = z.infer<typeof orgSetupSchema>;

interface OrgSetupFormInitialValues {
  organizationName: string;
  awsOrgId: string;
}

interface OrgSetupFormProps {
  onBack: () => void;
  onClose?: () => void;
  onNext: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
  onPhaseChange: (phase: OrgSetupPhase) => void;
  initialPhase?: OrgSetupPhase;
  initialValues?: OrgSetupFormInitialValues;
  intent?: OrgWizardIntent;
}

export function OrgSetupForm({
  onBack,
  onClose,
  onNext,
  onFooterChange,
  onPhaseChange,
  initialPhase = ORG_SETUP_PHASE.DETAILS,
  initialValues,
  intent = ORG_WIZARD_INTENT.FULL,
}: OrgSetupFormProps) {
  const { data: session } = useSession();
  const stackSetExternalId = session?.tenantId ?? "";
  const { organizationId } = useOrgSetupStore();
  const { toast } = useToast();
  const { copied: isExternalIdCopied, copy: copyExternalId } = useClipboard({
    timeout: 1500,
  });
  const { copied: isTemplateUrlCopied, copy: copyTemplateUrl } = useClipboard({
    timeout: 1500,
  });
  const [setupPhase, setSetupPhase] = useState<OrgSetupPhase>(initialPhase);
  const [isSaving, setIsSaving] = useState(false);
  const formId = "org-wizard-setup-form";

  const isReadOnlyOrgId = Boolean(initialValues?.awsOrgId);

  const form = useForm<OrgSetupFormData>({
    resolver: zodResolver(orgSetupSchema),
    mode: "onChange",
    reValidateMode: "onChange",
    defaultValues: {
      organizationName: initialValues?.organizationName ?? "",
      awsOrgId: initialValues?.awsOrgId ?? "",
      roleArn: "",
      stackSetDeployed: false,
    },
  });
  const {
    control,
    handleSubmit,
    formState: { errors, isSubmitting, isValid },
    setError,
    watch,
  } = form;

  const awsOrgId = watch("awsOrgId") || "";
  const isOrgIdValid = /^o-[a-z0-9]{10,32}$/.test(awsOrgId.trim());
  const templateLinks = stackSetExternalId
    ? getAWSCredentialsTemplateLinks(stackSetExternalId)
    : null;
  const orgQuickLink = templateLinks?.cloudformationOrgQuickLink;

  const { apiError, setApiError, submitOrganizationSetup } =
    useOrgSetupSubmission({
      stackSetExternalId,
      onNext,
      setFieldError: (field, message) => {
        setError(field, { message });
      },
    });

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
      backDisabled: isSubmitting,
      onBack: () => setSetupPhase(ORG_SETUP_PHASE.DETAILS),
      showAction: true,
      actionLabel: "Authenticate",
      actionDisabled: isSubmitting || !isValid || !stackSetExternalId,
      actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: formId,
    });
  }, [
    formId,
    intent,
    isOrgIdValid,
    isSaving,
    isSubmitting,
    isValid,
    onBack,
    onFooterChange,
    stackSetExternalId,
    setupPhase,
  ]);

  const handleContinueToAccess = () => {
    setApiError(null);

    if (!isOrgIdValid) {
      setError("awsOrgId", {
        message: awsOrgId.trim()
          ? "Must be a valid AWS Organization ID (e.g., o-abc123def4)"
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

    void handleSubmit((data) => submitOrganizationSetup(data))(event);
  };

  useEffect(() => {
    if (!apiError) return;
    document
      .getElementById(formId)
      ?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [apiError, formId]);

  return (
    <Form {...form}>
      <form
        id={formId}
        onSubmit={handleFormSubmit}
        className="flex flex-col gap-5"
      >
        {setupPhase === ORG_SETUP_PHASE.DETAILS && (
          <div className="flex flex-col gap-6">
            <div className="flex items-center gap-4">
              <AWSProviderBadge size={32} />
              <h3 className="text-base font-semibold">
                Amazon Web Services (AWS) / Organization Details
              </h3>
            </div>

            <p className="text-muted-foreground text-sm">
              Enter the Organization ID for the accounts you want to add to
              Prowler.
            </p>
          </div>
        )}

        {setupPhase === ORG_SETUP_PHASE.ACCESS && (
          <div className="flex flex-col gap-8">
            <div className="flex items-center gap-4">
              <AWSProviderBadge size={32} />
              <h3 className="text-base font-semibold">
                Amazon Web Services (AWS) / Authentication Details
              </h3>
            </div>
          </div>
        )}

        {setupPhase === ORG_SETUP_PHASE.ACCESS && isSubmitting && (
          <div className="flex min-h-[220px] items-center justify-center">
            <div className="flex items-center gap-3 py-2">
              <Spinner className="size-6" />
              <p className="text-sm font-medium">Gathering AWS Accounts...</p>
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

        {setupPhase === ORG_SETUP_PHASE.DETAILS && (
          <div className="flex flex-col gap-4">
            <WizardInputField
              control={control}
              name="awsOrgId"
              label="Organization ID"
              labelPlacement="outside"
              placeholder="e.g. o-123456789-abcdefg"
              isRequired
              normalizeValue={(value) => value.toLowerCase()}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
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
              If left blank, Prowler will use the Organization name stored in
              AWS.
            </p>
          </div>
        )}

        {setupPhase === ORG_SETUP_PHASE.ACCESS && !isSubmitting && (
          <div className="flex flex-col gap-8">
            {/* External ID - shown first for both deployment steps */}
            <div className="flex flex-col gap-4">
              <p className="text-text-neutral-primary text-sm leading-7 font-normal">
                Use the following <strong>External ID</strong> when deploying
                the CloudFormation Stack and StackSet.
              </p>
              <div className="flex items-center gap-3">
                <span className="text-text-neutral-tertiary text-xs">
                  External ID:
                </span>
                <div className="bg-bg-neutral-tertiary border-border-input-primary flex h-10 max-w-full items-center gap-3 rounded-full border px-4">
                  <span className="truncate text-xs font-medium">
                    {stackSetExternalId ||
                      "Loading organization external ID..."}
                  </span>
                  <button
                    type="button"
                    disabled={!stackSetExternalId}
                    onClick={() => copyExternalId(stackSetExternalId)}
                    className="text-text-neutral-secondary hover:text-text-neutral-primary shrink-0 transition-colors"
                    aria-label="Copy external ID"
                  >
                    {isExternalIdCopied ? (
                      <Check className="size-4" />
                    ) : (
                      <Copy className="size-4" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* Step 1: Management account - CloudFormation Stack */}
            <div className="flex flex-col gap-4">
              <p className="text-text-neutral-primary text-sm leading-7 font-normal">
                1) Deploy the ProwlerScan role in your{" "}
                <strong>management account</strong> using a CloudFormation
                Stack.
              </p>
              <Button
                variant="outline"
                size="lg"
                className="border-border-input-primary bg-bg-input-primary text-button-tertiary hover:bg-bg-input-primary active:bg-bg-input-primary h-12 w-full justify-start"
                disabled={!orgQuickLink}
                asChild
              >
                <a
                  href={orgQuickLink || "#"}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <ExternalLink className="size-5" />
                  <span>Create Stack in Management Account</span>
                </a>
              </Button>
            </div>

            {/* Step 2: Member accounts - CloudFormation StackSet */}
            <div className="flex flex-col gap-4">
              <p className="text-text-neutral-primary text-sm leading-7 font-normal">
                2) Deploy the ProwlerScan role to{" "}
                <strong>member accounts</strong> using a CloudFormation
                StackSet.
              </p>
              <p className="text-text-neutral-tertiary text-xs leading-5">
                Open the StackSets console, select{" "}
                <strong>Service-managed permissions</strong>, and paste the
                template URL below. Set the <strong>ExternalId</strong>{" "}
                parameter to the value shown above.
              </p>
              <div className="bg-bg-neutral-tertiary border-border-input-primary flex items-center gap-3 rounded-lg border px-4 py-2.5">
                <span className="text-text-neutral-primary min-w-0 flex-1 truncate font-mono text-xs">
                  {PROWLER_CF_TEMPLATE_URL}
                </span>
                <button
                  type="button"
                  onClick={() => copyTemplateUrl(PROWLER_CF_TEMPLATE_URL)}
                  className="text-text-neutral-secondary hover:text-text-neutral-primary shrink-0 transition-colors"
                  aria-label="Copy template URL"
                >
                  {isTemplateUrlCopied ? (
                    <Check className="size-4" />
                  ) : (
                    <Copy className="size-4" />
                  )}
                </button>
              </div>
              <Button
                variant="outline"
                size="lg"
                className="border-border-input-primary bg-bg-input-primary text-button-tertiary hover:bg-bg-input-primary active:bg-bg-input-primary h-12 w-full justify-start"
                disabled={!isExternalIdCopied}
                asChild
              >
                <a
                  href={STACKSET_CONSOLE_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <ExternalLink className="size-5" />
                  <span>Open StackSets Console</span>
                </a>
              </Button>
            </div>

            {/* Step 3: Role ARN + confirm */}
            <div className="flex flex-col gap-4">
              <p className="text-text-neutral-primary text-sm leading-7 font-normal">
                3) Paste the management account Role ARN and confirm both
                deployments are complete.
              </p>
            </div>

            <WizardInputField
              control={control}
              name="roleArn"
              label="Management Account Role ARN"
              labelPlacement="outside"
              placeholder="e.g. arn:aws:iam::123456789012:role/ProwlerScan"
              isRequired={false}
              requiredIndicator
            />

            <p className="text-text-neutral-tertiary text-sm">
              * It may take up to 60 seconds for AWS to generate the IAM Role
              ARN
            </p>

            <div className="flex items-start gap-4">
              <Controller
                name="stackSetDeployed"
                control={control}
                render={({ field }) => (
                  <>
                    <Checkbox
                      id="stackSetDeployed"
                      className="mt-0.5"
                      checked={field.value}
                      onCheckedChange={(checked) =>
                        field.onChange(Boolean(checked))
                      }
                    />
                    <label
                      htmlFor="stackSetDeployed"
                      className="text-text-neutral-tertiary text-xs leading-5 font-normal"
                    >
                      The Stack and StackSet have been successfully deployed in
                      AWS
                      <span className="text-text-error-primary">*</span>
                    </label>
                  </>
                )}
              />
            </div>
            {errors.stackSetDeployed && (
              <span className="text-text-error-primary text-xs">
                {errors.stackSetDeployed.message}
              </span>
            )}
          </div>
        )}
      </form>
    </Form>
  );
}
