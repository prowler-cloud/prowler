"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Check, Copy, ExternalLink, Loader2 } from "lucide-react";
import { FormEvent, useEffect, useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { z } from "zod";

import {
  createOrganization,
  createOrganizationSecret,
  getDiscovery,
  triggerDiscovery,
} from "@/actions/organizations/organizations";
import {
  buildOrgTreeData,
  getSelectableAccountIds,
} from "@/actions/organizations/organizations.adapter";
import { AWSProviderBadge } from "@/components/icons/providers-badge";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import { Input } from "@/components/shadcn/input/input";
import { TreeSpinner } from "@/components/shadcn/tree-view/tree-spinner";
import { getAWSCredentialsTemplateLinks } from "@/lib";
import { useOrgSetupStore } from "@/store/organizations/store";
import {
  DISCOVERY_STATUS,
  DiscoveryResult,
  ORG_SETUP_PHASE,
  OrgSetupPhase,
} from "@/types/organizations";

const DISCOVERY_POLL_INTERVAL_MS = 3000;
const DISCOVERY_MAX_RETRIES = 60;
const DEBUG_SCOPE = "[OrgSetupForm]";

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
      "Must be a valid IAM Role ARN (e.g., arn:aws:iam::123456789012:role/ProwlerOrgRole)",
    ),
  stackSetDeployed: z.boolean().refine((value) => value, {
    message: "You must confirm the StackSet deployment before continuing.",
  }),
});

type OrgSetupFormData = z.infer<typeof orgSetupSchema>;

interface OrgSetupFormProps {
  onBack: () => void;
  onNext: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
  onPhaseChange: (phase: OrgSetupPhase) => void;
}

export function OrgSetupForm({
  onBack,
  onNext,
  onFooterChange,
  onPhaseChange,
}: OrgSetupFormProps) {
  const debugLog = (message: string, payload?: unknown) => {
    if (process.env.NODE_ENV === "production") return;

    if (payload === undefined) {
      console.error(`${DEBUG_SCOPE} ${message}`);
      return;
    }

    console.error(`${DEBUG_SCOPE} ${message}`, payload);
  };

  const [apiError, setApiError] = useState<string | null>(null);
  const [isExternalIdCopied, setIsExternalIdCopied] = useState(false);
  const [stackSetExternalId] = useState(() => generateStackSetExternalId());
  const [setupPhase, setSetupPhase] = useState<OrgSetupPhase>(
    ORG_SETUP_PHASE.DETAILS,
  );
  const { setOrganization, setDiscovery, setSelectedAccountIds } =
    useOrgSetupStore();
  const formId = "org-wizard-setup-form";

  const {
    control,
    register,
    handleSubmit,
    formState: { errors, isSubmitting, isValid },
    setError,
    watch,
  } = useForm<OrgSetupFormData>({
    resolver: zodResolver(orgSetupSchema),
    mode: "onChange",
    reValidateMode: "onChange",
    defaultValues: {
      organizationName: "",
      awsOrgId: "",
      roleArn: "",
      stackSetDeployed: false,
    },
  });

  const awsOrgId = watch("awsOrgId") || "";
  const isOrgIdValid = /^o-[a-z0-9]{10,32}$/.test(awsOrgId.trim());
  const stackSetQuickLink =
    getAWSCredentialsTemplateLinks(stackSetExternalId).cloudformationQuickLink;

  useEffect(() => {
    onPhaseChange(setupPhase);
  }, [onPhaseChange, setupPhase]);

  useEffect(() => {
    if (setupPhase === ORG_SETUP_PHASE.DETAILS) {
      onFooterChange({
        showBack: true,
        backLabel: "Back",
        onBack,
        showAction: true,
        actionLabel: "Next",
        actionDisabled: !isOrgIdValid,
        actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
        actionFormId: formId,
      });
      return;
    }

    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isSubmitting,
      onBack: () => setSetupPhase(ORG_SETUP_PHASE.DETAILS),
      showAction: true,
      actionLabel: "Authenticate",
      actionDisabled: isSubmitting || !isValid,
      actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: formId,
    });
  }, [
    formId,
    isOrgIdValid,
    isSubmitting,
    isValid,
    onBack,
    onFooterChange,
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

  const handleFormSubmit = (event: FormEvent<HTMLFormElement>) => {
    if (setupPhase === ORG_SETUP_PHASE.DETAILS) {
      event.preventDefault();
      handleContinueToAccess();
      return;
    }

    void handleSubmit(onSubmit)(event);
  };

  const onSubmit = async (data: OrgSetupFormData) => {
    try {
      setApiError(null);
      debugLog("Authenticate submit started", {
        awsOrgId: data.awsOrgId,
        hasRoleArn: Boolean(data.roleArn),
        stackSetDeployed: data.stackSetDeployed,
      });
      const resolvedOrganizationName =
        data.organizationName?.trim() || data.awsOrgId;

      // Step 1: Create Organization
      const orgFormData = new FormData();
      orgFormData.set("name", resolvedOrganizationName);
      orgFormData.set("externalId", data.awsOrgId);

      const orgResult = await createOrganization(orgFormData);
      debugLog("createOrganization response received", {
        hasError: Boolean(orgResult?.error),
        hasErrorsArray: Boolean(orgResult?.errors?.length),
      });

      if (orgResult?.error) {
        handleServerError(orgResult, "Organization");
        return;
      }

      const orgId = orgResult.data.id;
      setOrganization(orgId, resolvedOrganizationName, data.awsOrgId);

      // Step 2: Create Organization Secret
      const secretFormData = new FormData();
      secretFormData.set("organizationId", orgId);
      secretFormData.set("roleArn", data.roleArn);
      secretFormData.set("externalId", stackSetExternalId);

      const secretResult = await createOrganizationSecret(secretFormData);
      debugLog("createOrganizationSecret response received", {
        hasError: Boolean(secretResult?.error),
        hasErrorsArray: Boolean(secretResult?.errors?.length),
      });

      if (secretResult?.error) {
        handleServerError(secretResult, "Secret");
        return;
      }

      // Step 3: Trigger Discovery
      const discoveryResult = await triggerDiscovery(orgId);
      debugLog("triggerDiscovery response received", {
        hasError: Boolean(discoveryResult?.error),
        discoveryId: discoveryResult?.data?.id ?? null,
      });

      if (discoveryResult?.error) {
        setApiError(discoveryResult.error);
        return;
      }

      const discoveryId = discoveryResult.data.id;

      const resolvedDiscoveryResult = await pollDiscoveryResult(
        orgId,
        discoveryId,
      );

      if (!resolvedDiscoveryResult) {
        debugLog("pollDiscoveryResult returned null (authentication failed)");
        return;
      }

      const selectableAccountIds = getSelectableAccountIds(
        resolvedDiscoveryResult,
      );
      buildOrgTreeData(resolvedDiscoveryResult);
      setDiscovery(discoveryId, resolvedDiscoveryResult);
      setSelectedAccountIds(selectableAccountIds);

      // Discovery succeeded; advance to next wizard step.
      debugLog("Authenticate flow succeeded, advancing to next step", {
        discoveryId,
      });
      onNext();
    } catch (error) {
      console.error(`${DEBUG_SCOPE} Unexpected authenticate error`, error);
      setApiError(
        "Authentication failed. Please verify the StackSet deployment and Role ARN, then try again.",
      );
    }
  };

  const pollDiscoveryResult = async (
    organizationId: string,
    discoveryId: string,
  ): Promise<DiscoveryResult | null> => {
    for (let attempt = 0; attempt < DISCOVERY_MAX_RETRIES; attempt += 1) {
      debugLog("Polling discovery status", {
        attempt: attempt + 1,
        maxAttempts: DISCOVERY_MAX_RETRIES,
        organizationId,
        discoveryId,
      });
      const result = await getDiscovery(organizationId, discoveryId);

      if (result?.error) {
        console.error(`${DEBUG_SCOPE} getDiscovery returned error`, {
          attempt: attempt + 1,
          error: result.error,
        });
        setApiError(
          `Authentication failed. Please verify the StackSet deployment and Role ARN, then try again. ${result.error}`,
        );
        return null;
      }

      const status = result.data.attributes.status;
      debugLog("Discovery status response", {
        attempt: attempt + 1,
        status,
      });

      if (status === DISCOVERY_STATUS.SUCCEEDED) {
        debugLog("Discovery succeeded");
        return result.data.attributes.result as DiscoveryResult;
      }

      if (status === DISCOVERY_STATUS.FAILED) {
        const backendError = result.data.attributes.error;
        console.error(`${DEBUG_SCOPE} Discovery failed`, {
          attempt: attempt + 1,
          backendError,
        });
        setApiError(
          backendError
            ? `Authentication failed. Please verify the StackSet deployment and Role ARN, then try again. ${backendError}`
            : "Authentication failed. Please verify the StackSet deployment and Role ARN, then try again.",
        );
        return null;
      }

      await new Promise((resolve) =>
        setTimeout(resolve, DISCOVERY_POLL_INTERVAL_MS),
      );
    }

    setApiError(
      "Authentication timed out. Please verify the credentials and try again.",
    );
    console.error(`${DEBUG_SCOPE} Discovery polling timed out`, {
      maxAttempts: DISCOVERY_MAX_RETRIES,
      pollIntervalMs: DISCOVERY_POLL_INTERVAL_MS,
    });
    return null;
  };

  const handleServerError = (
    result: {
      error?: string;
      errors?: Array<{ detail: string; source?: { pointer: string } }>;
    },
    context: string,
  ) => {
    console.error(`${DEBUG_SCOPE} handleServerError`, {
      context,
      error: result.error ?? null,
      errors: result.errors ?? [],
    });
    if (result.errors?.length) {
      for (const err of result.errors) {
        const pointer = err.source?.pointer ?? "";

        if (pointer.includes("external_id") && context === "Organization") {
          setError("awsOrgId", { message: err.detail });
          setApiError(err.detail);
        } else if (pointer.includes("name")) {
          setError("organizationName", { message: err.detail });
        } else {
          setApiError(err.detail);
        }
      }
    } else {
      setApiError(result.error ?? `Failed to create ${context}`);
    }
  };

  useEffect(() => {
    if (!apiError) return;
    document
      .getElementById(formId)
      ?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [apiError, formId]);

  return (
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

      {setupPhase === ORG_SETUP_PHASE.ACCESS && !isSubmitting && (
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
            <TreeSpinner className="size-6" />
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
          <div className="flex flex-col gap-1.5">
            <label htmlFor="awsOrgId" className="text-sm font-medium">
              Organization ID
            </label>
            <Input
              id="awsOrgId"
              placeholder="e.g. o-123456789-abcdefg"
              required
              aria-required="true"
              {...register("awsOrgId")}
            />
            {errors.awsOrgId && (
              <span className="text-text-error-primary text-xs">
                {errors.awsOrgId.message}
              </span>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <label htmlFor="organizationName" className="text-sm font-medium">
              Name (optional)
            </label>
            <Input
              id="organizationName"
              placeholder=""
              {...register("organizationName")}
            />
            {errors.organizationName && (
              <span className="text-text-error-primary text-xs">
                {errors.organizationName.message}
              </span>
            )}
          </div>

          <p className="text-muted-foreground text-sm">
            If left blank, Prowler will use the Organization name stored in AWS.
          </p>
        </div>
      )}

      {setupPhase === ORG_SETUP_PHASE.ACCESS && !isSubmitting && (
        <div className="flex flex-col gap-8">
          <div className="flex flex-col gap-4">
            <p className="text-text-neutral-primary text-sm leading-7 font-normal">
              1) Launch the Prowler CloudFormation StackSet in your AWS Console.
            </p>
            <Button
              variant="outline"
              size="lg"
              className="border-border-input-primary bg-bg-input-primary text-button-tertiary hover:bg-bg-input-primary active:bg-bg-input-primary h-12 w-full justify-start"
              asChild
            >
              <a
                href={stackSetQuickLink}
                target="_blank"
                rel="noopener noreferrer"
              >
                <ExternalLink className="size-5" />
                <span>
                  Prowler CloudFormation StackSet for AWS Organizations
                </span>
              </a>
            </Button>
          </div>

          <div className="flex flex-col gap-4">
            <p className="text-text-neutral-primary text-sm leading-7 font-normal">
              2) Use the following Prowler External ID parameter in the
              StackSet.
            </p>
            <div className="flex items-center gap-3">
              <span className="text-text-neutral-tertiary text-xs">
                External ID:
              </span>
              <div className="bg-bg-neutral-tertiary border-border-input-primary flex h-10 max-w-full items-center gap-3 rounded-full border px-4">
                <span className="truncate text-xs font-medium">
                  {stackSetExternalId}
                </span>
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(stackSetExternalId);
                      setIsExternalIdCopied(true);
                      setTimeout(() => setIsExternalIdCopied(false), 1500);
                    } catch {
                      // Ignore clipboard errors (e.g., unsupported browser context).
                    }
                  }}
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

          <div className="flex flex-col gap-4">
            <p className="text-text-neutral-primary text-sm leading-7 font-normal">
              3) Copy the Prowler IAM Role ARN from AWS and confirm the StackSet
              is successfully deployed by clicking the checkbox below.
            </p>
          </div>

          <div className="flex flex-col gap-1.5">
            <label htmlFor="roleArn" className="text-sm font-medium">
              Role ARN
            </label>
            <Input
              id="roleArn"
              placeholder="e.g. arn:aws:iam::123456789012:role/ProwlerOrgRole"
              {...register("roleArn")}
            />
            {errors.roleArn && (
              <span className="text-text-error-primary text-xs">
                {errors.roleArn.message}
              </span>
            )}
          </div>

          <p className="text-text-neutral-tertiary text-sm">
            * It may take up to 60 seconds for AWS to generate the IAM Role ARN
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
                    className="text-text-neutral-primary text-sm leading-7 font-normal"
                  >
                    The StackSet has been successfully deployed in AWS
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

      {setupPhase === ORG_SETUP_PHASE.DETAILS && isSubmitting && (
        <div className="text-muted-foreground flex items-center justify-end gap-2 text-sm">
          <Loader2 className="size-4 animate-spin" />
          Setting up organization...
        </div>
      )}
    </form>
  );
}

function generateStackSetExternalId() {
  const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const parts = [3, 4, 4, 3, 6, 6];

  return parts
    .map((length) =>
      Array.from({ length }, () =>
        characters.charAt(Math.floor(Math.random() * characters.length)),
      ).join(""),
    )
    .join("-");
}
