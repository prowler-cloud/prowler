"use client";

import { refreshRegistryCredential } from "@/actions/registry/registry";
import { toast } from "@/components/shadcn/toast";
import { isActiveRegistryCredential } from "@/lib/registry-credential-task";
import type { TaskKindHandler } from "@/store/task-watcher/store";
import { REGISTRY_CREDENTIAL_READ } from "@/types/registry";

const invalidKeyToast = () =>
  toast({
    variant: "destructive",
    title: "Registry key validation failed",
    description:
      "The submitted Registry key could not be validated. Connect a new key from the Registry page.",
  });

/**
 * Notifies the outcome of a Registry credential validation task resumed after
 * a reload. In-session submissions are awaited by the access dialog instead
 * (`notifyHandler: false`), which owns the inline feedback while it is open.
 */
export const registryCredentialTaskHandler: TaskKindHandler = {
  onReady: async () => {
    const read = await refreshRegistryCredential();
    if (
      read.status === REGISTRY_CREDENTIAL_READ.STATUS &&
      isActiveRegistryCredential(read.credential)
    ) {
      toast({ title: "Registry connected" });
      return;
    }
    invalidKeyToast();
  },
  onError: (task) => {
    toast({
      variant: "destructive",
      title: "Registry key validation failed",
      description:
        task.error || "The Registry key validation task failed unexpectedly.",
    });
  },
};
