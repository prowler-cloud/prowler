"use client";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { useAuth } from "@/hooks/use-auth";

/** Cloudy has no paid plan: the registry upgrade prompt never renders. */
export function RegistryUpgradePrompt() {
  return null;
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
