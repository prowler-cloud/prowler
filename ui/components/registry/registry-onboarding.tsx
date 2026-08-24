import { Button } from "@/components/shadcn/button/button";
import type { RegistryTenantArtifact } from "@/types/registry";

export function RegistryOnboarding({
  tenantArtifacts,
  validationPending,
  onConnect,
}: {
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
    <section aria-live="polite" className="mx-auto max-w-2xl py-12 text-center">
      <h1 className="text-xl font-semibold">{title}</h1>
      <p className="text-text-neutral-secondary mt-3 text-sm">{copy}</p>
      <p className="text-text-neutral-secondary mt-3 text-sm">
        {tenantArtifacts.length} preserved tenant artifact
        {tenantArtifacts.length === 1 ? "" : "s"} remain in My artifacts.
      </p>
      {!validationPending && (
        <Button className="mt-6" onClick={onConnect} type="button">
          Connect Registry
        </Button>
      )}
      <Button asChild className="mt-6" variant="outline">
        <a
          href="https://registry.prowler.com"
          rel="noopener noreferrer"
          target="_blank"
        >
          Open Registry (opens in a new tab)
        </a>
      </Button>
    </section>
  );
}
