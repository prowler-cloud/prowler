import { redirect } from "next/navigation";

import { getRegistryBootstrap } from "@/actions/registry/registry";
import { RegistryAccessBoundary } from "@/components/registry/registry-access-boundary";
import { REGISTRY_FAILURE } from "@/types/registry";

export const dynamic = "force-dynamic";

export default async function RegistryPage() {
  const bootstrap = await getRegistryBootstrap();
  if (bootstrap.status === REGISTRY_FAILURE.ACCESS_DENIED) redirect("/profile");

  return (
    <RegistryAccessBoundary initialLeaseDurationMs={bootstrap.leaseDurationMs}>
      {null}
    </RegistryAccessBoundary>
  );
}
