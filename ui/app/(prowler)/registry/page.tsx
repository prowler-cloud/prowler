import { Package } from "lucide-react";
import { redirect } from "next/navigation";

import { getRegistryBootstrap } from "@/actions/registry/registry";
import { RegistryExplorer } from "@/components/registry/registry-explorer";
import { ContentLayout } from "@/components/shadcn/content-layout/content-layout";
import { readRegistryPresentation } from "@/lib/registry/presentation";
import { REGISTRY_FAILURE } from "@/types/registry";

export const dynamic = "force-dynamic";

export default async function RegistryPage() {
  const bootstrap = await getRegistryBootstrap();
  if (bootstrap.status === REGISTRY_FAILURE.ACCESS_DENIED) redirect("/profile");

  return (
    <ContentLayout title="Registry" icon={<Package />}>
      <RegistryExplorer
        initialState={bootstrap.state}
        registryUrl={readRegistryPresentation().registryUrl}
      />
    </ContentLayout>
  );
}
