"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  createOrganization,
  createOrganizationSecret,
  triggerDiscovery,
} from "@/actions/organizations/organizations";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import { Input } from "@/components/shadcn/input/input";
import { useOrgSetupStore } from "@/store/organizations/store";

const orgSetupSchema = z.object({
  organizationName: z
    .string()
    .min(3, "Organization name must be at least 3 characters"),
  awsOrgId: z
    .string()
    .regex(
      /^o-[a-z0-9]{10,32}$/,
      "Must be a valid AWS Organization ID (e.g., o-abc123def4)",
    ),
  roleArn: z
    .string()
    .regex(
      /^arn:aws:iam::\d{12}:role\//,
      "Must be a valid IAM Role ARN (e.g., arn:aws:iam::123456789012:role/ProwlerOrgRole)",
    ),
  externalId: z.string().min(1, "External ID is required"),
});

type OrgSetupFormData = z.infer<typeof orgSetupSchema>;

interface OrgSetupFormProps {
  onBack: () => void;
  onNext: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function OrgSetupForm({
  onBack,
  onNext,
  onFooterChange,
}: OrgSetupFormProps) {
  const [apiError, setApiError] = useState<string | null>(null);
  const { setOrganization, setDiscovery } = useOrgSetupStore();
  const formId = "org-wizard-setup-form";

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting, isValid },
    setError,
  } = useForm<OrgSetupFormData>({
    resolver: zodResolver(orgSetupSchema),
    mode: "onChange",
    reValidateMode: "onChange",
    defaultValues: {
      organizationName: "",
      awsOrgId: "",
      roleArn: "",
      externalId: "",
    },
  });

  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isSubmitting,
      onBack,
      showAction: true,
      actionLabel: "Next",
      actionDisabled: isSubmitting || !isValid,
      actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: formId,
    });
  }, [formId, isSubmitting, isValid, onBack, onFooterChange]);

  const onSubmit = async (data: OrgSetupFormData) => {
    setApiError(null);

    // Step 1: Create Organization
    const orgFormData = new FormData();
    orgFormData.set("name", data.organizationName);
    orgFormData.set("externalId", data.awsOrgId);

    const orgResult = await createOrganization(orgFormData);

    if (orgResult?.error) {
      handleServerError(orgResult, "Organization");
      return;
    }

    const orgId = orgResult.data.id;

    // Step 2: Create Organization Secret
    const secretFormData = new FormData();
    secretFormData.set("organizationId", orgId);
    secretFormData.set("roleArn", data.roleArn);
    secretFormData.set("externalId", data.externalId);

    const secretResult = await createOrganizationSecret(secretFormData);

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

    // Store in Zustand and advance
    setOrganization(orgId, data.organizationName, data.awsOrgId);
    setDiscovery(discoveryId, null as never);
    onNext();
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

        if (pointer.includes("external_id")) {
          setError("awsOrgId", { message: err.detail });
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

  return (
    <form
      id={formId}
      onSubmit={handleSubmit(onSubmit)}
      className="flex flex-col gap-5"
    >
      <div className="flex flex-col gap-1">
        <h3 className="text-lg font-semibold">Organization Details</h3>
        <p className="text-muted-foreground text-sm">
          Enter your AWS Organization details to discover all accounts.
        </p>
      </div>

      {apiError && (
        <div className="border-destructive/50 bg-destructive/10 text-destructive rounded-md border px-4 py-3 text-sm">
          {apiError}
        </div>
      )}

      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="organizationName" className="text-sm font-medium">
            Organization Name
          </label>
          <Input
            id="organizationName"
            placeholder="e.g. My AWS Organization"
            {...register("organizationName")}
          />
          {errors.organizationName && (
            <span className="text-destructive text-xs">
              {errors.organizationName.message}
            </span>
          )}
        </div>

        <div className="flex flex-col gap-1.5">
          <label htmlFor="awsOrgId" className="text-sm font-medium">
            AWS Organization ID
          </label>
          <Input
            id="awsOrgId"
            placeholder="e.g. o-abc123def4"
            {...register("awsOrgId")}
          />
          {errors.awsOrgId && (
            <span className="text-destructive text-xs">
              {errors.awsOrgId.message}
            </span>
          )}
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
            <span className="text-destructive text-xs">
              {errors.roleArn.message}
            </span>
          )}
        </div>

        <div className="flex flex-col gap-1.5">
          <label htmlFor="externalId" className="text-sm font-medium">
            External ID
          </label>
          <Input
            id="externalId"
            placeholder="Enter the external ID for role assumption"
            {...register("externalId")}
          />
          {errors.externalId && (
            <span className="text-destructive text-xs">
              {errors.externalId.message}
            </span>
          )}
        </div>
      </div>

      {isSubmitting && (
        <div className="text-muted-foreground flex items-center justify-end gap-2 text-sm">
          <Loader2 className="size-4 animate-spin" />
          Setting up organization...
        </div>
      )}
    </form>
  );
}
