"use client";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { useAuth } from "@/hooks/use-auth";
import { useCloudUpgradeStore } from "@/store/cloud-upgrade/store";
import { PAID_PLAN_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

export function RegistryUpgradePrompt() {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  return (
    <Alert>
      <AlertTitle>Registry is available on paid plans</AlertTitle>
      <AlertDescription>
        Unlock custom providers, security checks, and compliance frameworks.
        <Button
          type="button"
          onClick={() => openCloudUpgrade(PAID_PLAN_UPGRADE_FEATURE.REGISTRY)}
        >
          Unlock Registry
        </Button>
      </AlertDescription>
    </Alert>
  );
}

export function RegistrySetupPrompt() {
  const { permissions } = useAuth();
  return (
    <Alert>
      <AlertTitle>Registry is not connected yet</AlertTitle>
      <AlertDescription>
        {permissions.manage_registry === true ? (
          <>
            Connect your Registry API key to load custom providers.
            <Button asChild variant="outline">
              <a href="/registry">Connect Registry</a>
            </Button>
          </>
        ) : (
          "Ask an administrator to connect Registry before adding custom providers."
        )}
      </AlertDescription>
    </Alert>
  );
}
