"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";

import { updateProvider } from "@/actions/providers/providers";
import { scanOnDemand } from "@/actions/scans";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { ToastAction, useToast } from "@/components/shadcn";
import { EntityInfo } from "@/components/shadcn/entities";
import { Form } from "@/components/shadcn/form";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { TreeStatusIcon } from "@/components/shadcn/tree-view/tree-status-icon";
import { UsageLimitMessage } from "@/components/shared/usage-limit-message";
import { getActionErrorMessage, hasActionError } from "@/lib/action-errors";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { ApiError, SCAN_JOBS_TAB } from "@/types";
import { TREE_ITEM_STATUS } from "@/types/tree";

import { awsQuickNameSchema, AwsQuickNameValues } from "../aws-quick.utils";

export const AWS_QUICK_NAME_FORM_ID = "aws-quick-name-form";

interface AwsQuickNameStepProps {
  canLaunchScan: boolean;
  onClose: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function AwsQuickNameStep({
  canLaunchScan,
  onClose,
  onFooterChange,
}: AwsQuickNameStepProps) {
  const { toast } = useToast();
  const { providerId, providerUid, setProvider } = useProviderWizardStore();
  const [isFinishing, setIsFinishing] = useState(false);
  const form = useForm<AwsQuickNameValues>({
    resolver: zodResolver(awsQuickNameSchema),
    mode: "onChange",
    defaultValues: { alias: "" },
  });

  const actionLabel = (() => {
    if (isFinishing) return canLaunchScan ? "Launching scan..." : "Saving...";
    return canLaunchScan ? "Launch scan" : "Finish";
  })();

  useEffect(() => {
    onFooterChange({
      showBack: false,
      backLabel: "Back",
      showAction: true,
      actionLabel,
      actionLoading: isFinishing,
      actionDisabled: isFinishing || !providerId,
      actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: AWS_QUICK_NAME_FORM_ID,
    });
  }, [actionLabel, isFinishing, onFooterChange, providerId]);

  const saveAlias = async (alias: string) => {
    if (!providerId || !alias) return true;

    const formData = new FormData();
    formData.set(ProviderCredentialFields.PROVIDER_ID, providerId);
    formData.set(ProviderCredentialFields.PROVIDER_ALIAS, alias);
    const data = await updateProvider(formData);

    if (data?.errors?.length) {
      const detail = (data.errors as ApiError[])[0]?.detail ?? "";
      form.setError("alias", { type: "server", message: detail });
      return false;
    }

    setProvider({
      id: providerId,
      type: "aws",
      uid: providerUid ?? "",
      alias,
    });
    return true;
  };

  const launchScan = async () => {
    if (!providerId) return;

    const formData = new FormData();
    formData.set("providerId", providerId);
    const result = await scanOnDemand(formData);

    if (hasActionError(result)) {
      toast({
        variant: "destructive",
        title: "Account connected, but the scan did not start",
        description: getActionErrorMessage(result),
      });
      return;
    }

    toast({
      title: "Scan launched",
      description: "Your first AWS scan is running.",
      action: (
        <ToastAction altText="Go to scans" asChild>
          <Link href={`/scans?tab=${SCAN_JOBS_TAB.ACTIVE}`}>Go to scans</Link>
        </ToastAction>
      ),
    });
  };

  const onSubmit = form.handleSubmit(async ({ alias }) => {
    if (isFinishing) return;
    setIsFinishing(true);

    try {
      const saved = await saveAlias(alias.trim());
      if (!saved) return;

      if (canLaunchScan) {
        await launchScan();
      }
      onClose();
    } finally {
      setIsFinishing(false);
    }
  });

  if (isFinishing) {
    return (
      <div className="flex min-h-[220px] items-center justify-center">
        <div className="flex items-center gap-3 py-2">
          <Spinner className="size-6" />
          <p className="text-sm font-medium">
            {canLaunchScan ? "Launching scan..." : "Saving..."}
          </p>
        </div>
      </div>
    );
  }

  return (
    <Form {...form}>
      <form
        id={AWS_QUICK_NAME_FORM_ID}
        onSubmit={onSubmit}
        className="flex flex-col gap-6"
      >
        <div className="flex items-center gap-3">
          <TreeStatusIcon
            status={TREE_ITEM_STATUS.SUCCESS}
            className="size-6"
          />
          <h3 className="text-base font-semibold">
            It worked! Everything seems to be connected.
          </h3>
        </div>

        <p className="text-text-neutral-secondary text-sm">
          Give this account a name so your team can recognise it, and you are
          good to go.
        </p>

        {providerUid && (
          <EntityInfo
            cloudProvider="aws"
            entityAlias={providerUid}
            entityId={providerUid}
            idLabel="Account"
          />
        )}

        <WizardInputField
          control={form.control}
          name="alias"
          label="Name (optional)"
          labelPlacement="outside"
          placeholder="e.g. Production"
          isRequired={false}
        />

        {!canLaunchScan && <UsageLimitMessage />}
      </form>
    </Form>
  );
}
