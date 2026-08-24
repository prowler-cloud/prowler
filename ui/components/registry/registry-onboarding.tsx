import { type Ref } from "react";

import { Button } from "@/components/shadcn/button/button";
import { Card, CardContent } from "@/components/shadcn/card/card";
import type { RegistryTenantArtifact } from "@/types/registry";

export function RegistryOnboarding({
  tenantArtifacts,
  validationPending,
  onConnect,
  connectButtonRef,
}: {
  connectButtonRef?: Ref<HTMLButtonElement>;
  tenantArtifacts: RegistryTenantArtifact[];
  validationPending: boolean;
  onConnect: () => void;
}) {
  const title = validationPending
    ? "Registry validation in progress"
    : "Connect Registry";
  const copy = validationPending
    ? "Your Registry key is being validated. Catalog exploration will be available after validation succeeds."
    : "Connect a Registry key to browse available artifacts.";

  return (
    <section aria-live="polite" className="py-12">
      <Card variant="base" padding="lg" className="mx-auto max-w-2xl">
        <CardContent className="flex flex-col items-center gap-4 py-8 text-center">
          <div className="flex flex-col items-center gap-1">
            <h2 className="text-text-neutral-primary text-xl font-semibold">
              {title}
            </h2>
            <p className="text-text-neutral-secondary max-w-md text-sm">
              {copy}
            </p>
            {tenantArtifacts.length > 0 && (
              <p className="text-text-neutral-secondary max-w-md text-sm">
                Your {tenantArtifacts.length} preserved tenant artifact
                {tenantArtifacts.length === 1 ? "" : "s"} will remain available
                in My artifacts.
              </p>
            )}
          </div>
          <div className="flex flex-wrap justify-center gap-3">
            {!validationPending && (
              <Button
                onClick={onConnect}
                ref={connectButtonRef}
                size="sm"
                type="button"
              >
                Connect Registry
              </Button>
            )}
            <Button asChild size="sm" variant="outline">
              <a
                aria-label="Explore Prowler Registry (opens in a new tab)"
                href="https://registry.prowler.com"
                rel="noopener noreferrer"
                target="_blank"
              >
                Explore Prowler Registry
              </a>
            </Button>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
