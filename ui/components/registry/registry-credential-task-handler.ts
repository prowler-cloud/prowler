"use client";

import { refreshRegistryCredential } from "@/actions/registry/registry";
import { toast } from "@/components/shadcn/toast";
import {
  getRegistryCredentialFailureMessage,
  isActiveRegistryCredential,
  isRegistryCredentialTaskSuccessful,
} from "@/lib/registry-credential-task";
import type { TaskKindHandler } from "@/store/task-watcher/store";
import { REGISTRY_CREDENTIAL_READ } from "@/types/registry";

const invalidKeyToast = (result?: unknown) => {
  toast({
    variant: "destructive",
    title: "Registry key validation failed",
    description:
      getRegistryCredentialFailureMessage(result) ??
      "The submitted Registry key could not be validated. Connect a new key from the Registry page.",
  });
  window.dispatchEvent(new Event("registry-credential-changed"));
};

/** One notification after task success and an authoritative credential read. */
export const registryCredentialTaskHandler: TaskKindHandler = {
  onReady: async (task) => {
    if (!isRegistryCredentialTaskSuccessful(task.result)) {
      invalidKeyToast(task.result);
      return;
    }
    const read = await refreshRegistryCredential().catch(() => ({
      status: "error" as const,
    }));
    if (
      read.status === REGISTRY_CREDENTIAL_READ.STATUS &&
      isActiveRegistryCredential(read.credential)
    ) {
      toast({ title: "Registry connected" });
      window.dispatchEvent(new Event("registry-credential-changed"));
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
    window.dispatchEvent(new Event("registry-credential-changed"));
  },
};
