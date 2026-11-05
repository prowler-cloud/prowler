"use client";

import { usePartialScanStore } from "@/store";

import { RecheckResourceModal } from "./recheck-resource-modal";

// One global modal, like Jira dispatch: it remounts per target so its state
// (pending, error) never leaks between resources.
export const RecheckResourceModalHost = () => {
  const activeTarget = usePartialScanStore((state) => state.activeTarget);
  const closePartialScan = usePartialScanStore(
    (state) => state.closePartialScan,
  );

  if (!activeTarget) return null;

  return (
    <RecheckResourceModal
      key={activeTarget.resourceUid}
      isOpen
      onOpenChange={(open) => !open && closePartialScan()}
      target={activeTarget}
    />
  );
};
