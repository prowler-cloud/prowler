import Link from "next/link";

import { toast, ToastAction } from "@/components/shadcn/toast";
import type { RegistryMutationResult } from "@/types/registry";

export function notifyRegistryArtifactOutcome(
  result: RegistryMutationResult,
): void {
  if (result.status === "confirmed") {
    toast({
      title: "Artifact added",
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
      title: "Artifact could not be added",
      description:
        result.status === "refused"
          ? result.message
          : result.status === "refresh_failed"
            ? "Installation could not be confirmed. Refresh Registry before retrying."
            : "Check the Registry connection and try again.",
    });
  }
}
