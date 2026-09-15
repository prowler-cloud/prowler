import Link from "next/link";

import { toast, ToastAction } from "@/components/shadcn/toast";
import {
  REGISTRY_INSTALL_OPERATION,
  type RegistryInstallOperation,
  type RegistryMutationResult,
} from "@/types/registry";

export function notifyRegistryArtifactOutcome(
  result: RegistryMutationResult,
  operation: RegistryInstallOperation = REGISTRY_INSTALL_OPERATION.ADD,
): void {
  const isUpdate = operation === REGISTRY_INSTALL_OPERATION.UPDATE;
  if (result.status === "confirmed") {
    toast({
      title: isUpdate ? "Artifact updated" : "Artifact added",
      action: (
        <ToastAction altText="Go to Providers" asChild>
          <Link href="/providers">Go to Providers</Link>
        </ToastAction>
      ),
    });
    window.dispatchEvent(
      new CustomEvent("registry-artifacts-changed", {
        detail: result.tenantArtifacts,
      }),
    );
  } else {
    toast({
      variant: "destructive",
      title: isUpdate
        ? "Artifact could not be updated"
        : "Artifact could not be added",
      description:
        result.status === "refused"
          ? result.message
          : result.status === "refresh_failed"
            ? isUpdate
              ? "Update could not be confirmed. Refresh Registry before retrying."
              : "Installation could not be confirmed. Refresh Registry before retrying."
            : "Check the Registry connection and try again.",
    });
  }
}
