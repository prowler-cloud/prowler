"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Check, Copy, ExternalLink, Loader2 } from "lucide-react";
import { useSession } from "next-auth/react";
import { FormEvent, useEffect, useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { z } from "zod";

import {
  createOrganization,
  createOrganizationSecret,
  getDiscovery,
  listOrganizationsByExternalId,
  listOrganizationSecretsByOrganizationId,
  triggerDiscovery,
  updateOrganizationSecret,
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
  const { data: session } = useSession();
  const [apiError, setApiError] = useState<string | null>(null);
  const [isExternalIdCopied, setIsExternalIdCopied] = useState(false);
  const stackSetExternalId = session?.tenantId ?? "";
  const [setupPhase, setSetupPhase] = useState<OrgSetupPhase>(
    ORG_SETUP_PHASE.DETAILS,
  );
  const {
    setOrganization,
    setDiscovery,
    setSelectedAccountIds,
    clearValidationState,
  } = useOrgSetupStore();
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
  const awsOrgIdField = register("awsOrgId", {
    setValueAs: (value: unknown) =>
      typeof value === "string" ? value.toLowerCase() : value,
  });

  const awsOrgId = watch("awsOrgId") || "";
  const isOrgIdValid = /^o-[a-z0-9]{10,32}$/.test(awsOrgId.trim());
  const stackSetQuickLink =
    stackSetExternalId &&
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
      actionDisabled: isSubmitting || !isValid || !stackSetExternalId,
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
      clearValidationState();
      const resolvedOrganizationName =
        data.organizationName?.trim() || data.awsOrgId;

      // Step 1: Resolve existing organization by external_id. If missing, create it.
      const existingOrganizationsResult = await listOrganizationsByExternalId(
        data.awsOrgId,
      );

      if (existingOrganizationsResult?.error) {
        setApiError(existingOrganizationsResult.error);
        return;
      }

      const existingOrganization = Array.isArray(existingOrganizationsResult?.data)
        ? existingOrganizationsResult.data.find(
            (organization: {
              id: string;
              attributes?: { external_id?: string; org_type?: string };
            }) =>
              organization?.attributes?.external_id === data.awsOrgId &&
              organization?.attributes?.org_type === "aws",
          )
        : null;

      let orgId = existingOrganization?.id as string | undefined;

      if (!orgId) {
        const orgFormData = new FormData();
        orgFormData.set("name", resolvedOrganizationName);
        orgFormData.set("externalId", data.awsOrgId);

        const orgResult = await createOrganization(orgFormData);

        if (orgResult?.error) {
          handleServerError(orgResult, "Organization");
          return;
        }

        orgId = orgResult.data.id;
      }

      if (!orgId) {
        setApiError("Unable to resolve organization ID for authentication.");
        return;
      }

      const organizationNameForStore =
        existingOrganization?.attributes?.name ?? resolvedOrganizationName;
      setOrganization(orgId, organizationNameForStore, data.awsOrgId);

      // Step 2: Create or update organization secret.
      const existingSecretsResult =
        await listOrganizationSecretsByOrganizationId(orgId);

      if (existingSecretsResult?.error) {
        setApiError(existingSecretsResult.error);
        return;
      }

      const existingSecretId =
        Array.isArray(existingSecretsResult?.data) &&
        existingSecretsResult.data.length > 0
          ? (existingSecretsResult.data[0]?.id as string | undefined)
          : undefined;

      let secretResult;
      if (existingSecretId) {
        const patchSecretFormData = new FormData();
        patchSecretFormData.set("organizationSecretId", existingSecretId);
        patchSecretFormData.set("roleArn", data.roleArn);
        patchSecretFormData.set("externalId", stackSetExternalId);
        secretResult = await updateOrganizationSecret(patchSecretFormData);
      } else {
        const createSecretFormData = new FormData();
        createSecretFormData.set("organizationId", orgId);
        createSecretFormData.set("roleArn", data.roleArn);
        createSecretFormData.set("externalId", stackSetExternalId);
        secretResult = await createOrganizationSecret(createSecretFormData);
      }

      if (secretResult?.error) {
        handleServerError(secretResult, "Secret");
        return;
      }

      // Step 3: Trigger Discovery
      const discoveryResult = await triggerDiscovery(orgId);

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
        return;
      }

      const selectableAccountIds = getSelectableAccountIds(
        resolvedDiscoveryResult,
      );
      buildOrgTreeData(resolvedDiscoveryResult);
      setDiscovery(discoveryId, resolvedDiscoveryResult);
      setSelectedAccountIds(selectableAccountIds);

      // Discovery succeeded; advance to next wizard step.
      onNext();
    } catch {
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
      const result = await getDiscovery(organizationId, discoveryId);

      if (result?.error) {
        setApiError(
          `Authentication failed. Please verify the StackSet deployment and Role ARN, then try again. ${result.error}`,
        );
        return null;
      }

      const status = result.data.attributes.status;

      if (status === DISCOVERY_STATUS.SUCCEEDED) {
        return result.data.attributes.result as DiscoveryResult;
      }

      if (status === DISCOVERY_STATUS.FAILED) {
        const backendError = result.data.attributes.error;
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
    return null;
  };

  const handleServerError = (
    result: {
      error?: string;
      errors?: Array<{ detail: string; source?: { pointer: string } }>;
    },
    context: string,
  ) => {
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
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              {...awsOrgIdField}
              onInput={(event) => {
                const loweredValue = event.currentTarget.value.toLowerCase();
                if (event.currentTarget.value !== loweredValue) {
                  event.currentTarget.value = loweredValue;
                }
              }}
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
              disabled={!stackSetQuickLink}
              asChild
            >
              <a
                href={stackSetQuickLink || "#"}
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
                  {stackSetExternalId || "Loading organization external ID..."}
                </span>
                <button
                  type="button"
                  disabled={!stackSetExternalId}
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
