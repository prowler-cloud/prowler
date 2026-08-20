import { redirect } from "next/navigation";

import { auth } from "@/auth.config";
import { RegistryAccessBoundary } from "@/components/registry/registry-access-boundary";
import { REGISTRY_ACCESS } from "@/lib/registry/access";
import { evaluateRegistryAccess } from "@/lib/registry/access.server";

export const dynamic = "force-dynamic";

export default async function RegistryPage() {
  const access = await evaluateRegistryAccess((await auth())?.accessToken);
  if (access.status !== REGISTRY_ACCESS.ELIGIBLE) redirect("/profile");
  return (
    <RegistryAccessBoundary initialLeaseDurationMs={access.leaseDurationMs}>
      {null}
    </RegistryAccessBoundary>
  );
}
