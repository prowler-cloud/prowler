"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { getProviders } from "@/actions/providers";
import { createPartialScan } from "@/actions/scans";
import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { toast, ToastAction } from "@/components/shadcn/toast";
import {
  findProviderIdForTarget,
  getPartialScanErrorMessage,
  PARTIAL_SCAN_LAUNCH_ERROR,
} from "@/lib/partial-scans";
import type { PartialScanTarget } from "@/types/partial-scans";

export const RECHECK_RESOURCE_SUBMIT_LABEL = "Re-check resource";
export const PROVIDER_NOT_FOUND_ERROR =
  "We couldn't find the provider of this resource. Refresh the page and try again.";

interface RecheckResourceModalProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  target: PartialScanTarget;
}

const hasDisplayName = (name: string) => name.trim() !== "" && name !== "-";

export function RecheckResourceModal({
  isOpen,
  onOpenChange,
  target,
}: RecheckResourceModalProps) {
  const router = useRouter();
  const [isPending, setIsPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const resourceLabel = hasDisplayName(target.resourceName)
    ? target.resourceName
    : target.resourceUid;

  // Drill-down rows only know the provider by uid + type; the API needs its id.
  const resolveProviderId = async () => {
    if (target.providerId) return target.providerId;

    const response = await getProviders({
      filters: {
        "filter[uid]": target.providerUid,
        "filter[provider]": target.providerType,
      },
    });

    return findProviderIdForTarget(response?.data ?? [], target);
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (isPending) return;

    setIsPending(true);
    setError(null);

    try {
      const providerId = await resolveProviderId();
      if (!providerId) {
        setError(PROVIDER_NOT_FOUND_ERROR);
        return;
      }

      const result = await createPartialScan({
        providerId,
        resourceUids: [target.resourceUid],
      });
      const errorMessage = getPartialScanErrorMessage(result);
      if (errorMessage) {
        setError(errorMessage);
        return;
      }
      // An empty 2xx has no scan to follow, so it is not a launch.
      if (!result?.data?.id) {
        setError(PARTIAL_SCAN_LAUNCH_ERROR);
        return;
      }

      toast({
        title: "Re-check launched",
        description: `Only ${resourceLabel} is being re-checked. Its findings update once the scan completes.`,
        action: (
          <ToastAction altText="View scan in progress" asChild>
            <Link href="/scans?tab=active">View scan</Link>
          </ToastAction>
        ),
      });
      onOpenChange(false);
      router.refresh();
    } catch {
      setError(PARTIAL_SCAN_LAUNCH_ERROR);
    } finally {
      setIsPending(false);
    }
  };

  return (
    <Modal
      open={isOpen}
      // Escape and backdrop must not unmount the modal mid-request, or the
      // error would land on an unmounted component.
      onOpenChange={(open) => {
        if (!open && isPending) return;
        onOpenChange(open);
      }}
      title="Re-check this resource"
      description="Run a partial scan on a single resource instead of the whole provider."
      size="lg"
    >
      <form className="flex flex-col gap-5" onSubmit={handleSubmit}>
        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary rounded-xl border p-4">
          <p className="text-text-neutral-tertiary text-xs font-medium tracking-[0.08em] uppercase">
            Resource
          </p>
          <p className="text-text-neutral-primary mt-2 text-sm font-semibold break-all">
            {resourceLabel}
          </p>
          {resourceLabel !== target.resourceUid && (
            <p className="text-text-neutral-tertiary mt-1 text-xs break-all">
              {target.resourceUid}
            </p>
          )}
          {target.providerAlias && (
            <p className="text-text-neutral-secondary mt-2 text-xs">
              Provider:{" "}
              <span className="text-text-neutral-primary">
                {target.providerAlias}
              </span>
            </p>
          )}
        </div>

        <div className="text-text-neutral-secondary space-y-2 text-sm">
          <p>
            Only the checks that last reported on this resource run again. Its
            findings update when the scan completes; every other resource keeps
            the results of the latest full scan.
          </p>
          <p className="text-text-neutral-tertiary text-xs">
            Overviews and compliance do not change until the next full scan. A
            re-check is refused while the provider has a scan running or queued.
          </p>
        </div>

        {error && (
          <p role="alert" className="text-text-error-primary text-sm">
            {error}
          </p>
        )}

        <div className="flex w-full justify-end gap-4">
          <Button
            type="button"
            variant="ghost"
            size="lg"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
          >
            Cancel
          </Button>
          <Button type="submit" size="lg" disabled={isPending}>
            {isPending ? "Launching..." : RECHECK_RESOURCE_SUBMIT_LABEL}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
