import React from "react";

import { S3IntegrationCard } from "@/components/integrations";
import { ContentLayout } from "@/components/ui";

export default async function Integrations() {
  return (
    <ContentLayout title="Integrations" icon="lucide:puzzle">
      <div className="space-y-6">
        <div className="space-y-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Connect external services to enhance your security workflow and
            automatically export your scan results.
          </p>
        </div>

        <div className="grid gap-6">
          {/* Amazon S3 Integration */}
          <S3IntegrationCard />
        </div>
      </div>
    </ContentLayout>
  );
}
