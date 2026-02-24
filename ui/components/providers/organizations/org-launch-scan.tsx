"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { launchOrganizationScans } from "@/actions/scans/scans";
import { AWSProviderBadge } from "@/components/icons/providers-badge";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { TreeSpinner } from "@/components/shadcn/tree-view/tree-spinner";
import { TreeStatusIcon } from "@/components/shadcn/tree-view/tree-status-icon";
import { ToastAction, useToast } from "@/components/ui";
import { useOrgSetupStore } from "@/store/organizations/store";
import { TREE_ITEM_STATUS } from "@/types/tree";

interface OrgLaunchScanProps {
  onClose: () => void;
  onBack: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

const SCAN_SCHEDULE = {
  DAILY: "daily",
  SINGLE: "single",
} as const;

type ScanScheduleOption = (typeof SCAN_SCHEDULE)[keyof typeof SCAN_SCHEDULE];

export function OrgLaunchScan({
  onClose,
  onBack,
  onFooterChange,
}: OrgLaunchScanProps) {
  const router = useRouter();
  const { toast } = useToast();
  const { organizationExternalId, createdProviderIds, reset } =
    useOrgSetupStore();

  const [isLaunching, setIsLaunching] = useState(false);
  const [scheduleOption, setScheduleOption] = useState<ScanScheduleOption>(
    SCAN_SCHEDULE.DAILY,
  );
  const launchActionRef = useRef<() => void>(() => {});

  const handleLaunchScan = async () => {
    setIsLaunching(true);

    const result = await launchOrganizationScans(
      createdProviderIds,
      scheduleOption,
    );
    const successCount = result.successCount;

    setIsLaunching(false);
    reset();
    onClose();
    router.push("/providers");

    toast({
      title: "Scan Launched",
      description:
        scheduleOption === SCAN_SCHEDULE.DAILY
          ? `Daily scan scheduled for ${successCount} account${successCount !== 1 ? "s" : ""}.`
          : `Single scan launched for ${successCount} account${successCount !== 1 ? "s" : ""}.`,
      action: (
        <ToastAction altText="Go to scans" asChild>
          <Link href="/scans">Go to scans</Link>
        </ToastAction>
      ),
    });
  };

  launchActionRef.current = () => {
    void handleLaunchScan();
  };

  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isLaunching,
      onBack,
      showAction: true,
      actionLabel: "Launch scan",
      actionDisabled: isLaunching || createdProviderIds.length === 0,
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: () => {
        launchActionRef.current();
      },
    });
  }, [createdProviderIds.length, isLaunching, onBack, onFooterChange]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-8">
      <div className="flex flex-col gap-3">
        <div className="flex items-center gap-4">
          <AWSProviderBadge size={32} />
          <h3 className="text-base font-semibold">My Organization</h3>
        </div>

        <div className="ml-12 flex items-center gap-3">
          <span className="text-text-neutral-tertiary text-xs">UID:</span>
          <div className="bg-bg-neutral-tertiary border-border-input-primary inline-flex h-10 items-center rounded-full border px-4">
            <span className="text-xs font-medium">
              {organizationExternalId || "N/A"}
            </span>
          </div>
        </div>
      </div>

      {isLaunching ? (
        <div className="flex min-h-[220px] items-center justify-center">
          <div className="flex items-center gap-3 py-2">
            <TreeSpinner className="size-6" />
            <p className="text-sm font-medium">Launching scans...</p>
          </div>
        </div>
      ) : (
        <div className="flex max-w-2xl flex-col gap-6">
          <div className="flex items-center gap-3">
            <TreeStatusIcon
              status={TREE_ITEM_STATUS.SUCCESS}
              className="size-6"
            />
            <h3 className="text-sm font-semibold">Accounts Connected!</h3>
          </div>

          <p className="text-text-neutral-secondary text-sm">
            Your accounts are connected to Prowler and ready to Scan!
          </p>

          {createdProviderIds.length === 0 && (
            <p className="text-text-error-primary text-sm">
              No successfully connected accounts are available to launch scans.
              Go back and retry connection tests.
            </p>
          )}

          <div className="flex flex-col gap-4">
            <p className="text-text-neutral-secondary text-sm">
              Select a Prowler scan schedule for these accounts.
            </p>
            <Select
              value={scheduleOption}
              onValueChange={(value) =>
                setScheduleOption(value as ScanScheduleOption)
              }
              disabled={isLaunching}
            >
              <SelectTrigger className="w-full max-w-[376px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={SCAN_SCHEDULE.DAILY}>
                  Scan Daily (every 24 hours)
                </SelectItem>
                <SelectItem value={SCAN_SCHEDULE.SINGLE}>
                  Run a single scan (no recurring schedule)
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )}
    </div>
  );
}
