import React from "react";

import { getIntegrations } from "@/actions/integrations";
import { S3IntegrationCard } from "@/components/integrations";
import { ContentLayout } from "@/components/ui";

export default async function Integrations() {
  const integrations = await getIntegrations();

  return (
    <ContentLayout title="Integrations" icon="lucide:puzzle">
      <div className="space-y-6">
        <div className="space-y-4">
          <h2 className="text-xl font-semibold">Available Integrations</h2>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Connect external services to enhance your security workflow and
            automatically export your security findings.
          </p>
        </div>

        <div className="grid gap-6">
          {/* Amazon S3 Integration */}
          <S3IntegrationCard integrations={integrations?.data || []} />
        </div>
      </div>
    </ContentLayout>
  );
}
