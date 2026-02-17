"use client";

import { CheckCircle2, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { scheduleDaily } from "@/actions/scans/scans";
import { Badge, Button } from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { useOrgSetupStore } from "@/store/organizations/store";

interface OrgLaunchScanProps {
  onClose: () => void;
}

export function OrgLaunchScan({ onClose }: OrgLaunchScanProps) {
  const router = useRouter();
  const { toast } = useToast();
  const {
    organizationName,
    organizationExternalId,
    createdProviderIds,
    reset,
  } = useOrgSetupStore();

  const [isLaunching, setIsLaunching] = useState(false);

  const handleDone = () => {
    reset();
    onClose();
    router.push("/providers");
  };

  const handleLaunchScan = async () => {
    setIsLaunching(true);

    let successCount = 0;

    for (const providerId of createdProviderIds) {
      const formData = new FormData();
      formData.set("providerId", providerId);

      const result = await scheduleDaily(formData);
      if (!result?.error) {
        successCount++;
      }
    }

    setIsLaunching(false);
    reset();
    onClose();
    router.push("/providers");

    toast({
      title: "Scan Launched",
      description: `Daily scan scheduled for ${successCount} account${successCount !== 1 ? "s" : ""}.`,
    });
  };

  return (
    <div className="flex flex-col items-center gap-6 py-6">
      {/* Org info */}
      <div className="flex items-center gap-2">
        <Badge variant="outline">AWS</Badge>
        <span className="text-sm font-medium">{organizationName}</span>
        {organizationExternalId && (
          <Badge variant="secondary">{organizationExternalId}</Badge>
        )}
      </div>

      {/* Success message */}
      <div className="flex flex-col items-center gap-2">
        <CheckCircle2 className="size-12 text-green-500" />
        <h3 className="text-lg font-semibold">Accounts Connected!</h3>
        <p className="text-muted-foreground text-center text-sm">
          Your accounts are connected to Prowler and ready to scan!
        </p>
      </div>

      {/* Scan schedule info */}
      <div className="flex flex-col items-center gap-2">
        <p className="text-muted-foreground text-sm">
          Select a Prowler scan schedule for these accounts.
        </p>
        <div className="bg-muted/30 rounded-md border px-4 py-2 text-sm">
          Scan Daily (every 24 hours)
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-3">
        <Button type="button" variant="outline" onClick={handleDone}>
          Done
        </Button>
        <Button type="button" onClick={handleLaunchScan} disabled={isLaunching}>
          {isLaunching && <Loader2 className="mr-2 size-4 animate-spin" />}
          {isLaunching ? "Launching..." : "Launch Scan"}
        </Button>
      </div>
    </div>
  );
}
