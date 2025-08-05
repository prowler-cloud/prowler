import React from "react";

import { getIntegrations } from "@/actions/integrations";
import { getProviders } from "@/actions/providers";
import { S3IntegrationsManager } from "@/components/integrations/s3/s3-integrations-manager";
import { ContentLayout } from "@/components/ui";

export default async function S3Integrations() {
  const [integrations, providers] = await Promise.all([
    getIntegrations(
      new URLSearchParams({ "filter[integration_type]": "amazon_s3" }),
    ),
    getProviders({ pageSize: 100 }),
  ]);

  const s3Integrations = integrations?.data || [];
  const availableProviders = providers?.data || [];

  return (
    <ContentLayout title="Amazon S3">
      <div className="space-y-6">
        <div className="space-y-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Configure Amazon S3 integration to automatically export your scan
            results to S3 buckets.
          </p>

          <div className="rounded-lg border border-gray-200 bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-800">
            <h3 className="mb-3 text-sm font-semibold text-gray-900 dark:text-gray-100">
              Features:
            </h3>
            <ul className="grid grid-cols-1 gap-2 text-sm text-gray-600 dark:text-gray-300 md:grid-cols-2">
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                Automated scan result exports
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                Multi-Cloud support
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                Configurable export paths
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                IAM role and static credentials
              </li>
            </ul>
          </div>
        </div>

        <S3IntegrationsManager
          integrations={s3Integrations}
          providers={availableProviders}
        />
      </div>
    </ContentLayout>
  );
}
