import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getProvidersOverview } from "@/actions/overview/overview";
import {
  ProvidersOverview,
  SkeletonProvidersOverview,
} from "@/components/overview";
import { Header } from "@/components/ui";

export default function Home() {
  return (
    <>
      <Header title="Scan Overview" icon="solar:pie-chart-2-outline" />
      <Spacer y={4} />
      <div className="min-h-screen">
        <div className="container mx-auto space-y-8 px-0 py-6">
          {/* Providers Overview */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <Suspense fallback={<SkeletonProvidersOverview />}>
              <SSRProvidersOverview />
            </Suspense>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2"></div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2"></div>
        </div>
      </div>
    </>
  );
}

const SSRProvidersOverview = async () => {
  const providersOverview = await getProvidersOverview({});

  if (!providersOverview) {
    return <p>There is no providers overview info available</p>;
  }

  return <ProvidersOverview providersOverview={providersOverview} />;
};
