import React from "react";

import { getIntegrations } from "@/actions/integrations";
import { getProviders } from "@/actions/providers";
import { SecurityHubIntegrationsManager } from "@/components/integrations/security-hub/security-hub-integrations-manager";
import { ContentLayout } from "@/components/ui";

interface SecurityHubIntegrationsProps {
  searchParams: { [key: string]: string | string[] | undefined };
}

export default async function SecurityHubIntegrations({
  searchParams,
}: SecurityHubIntegrationsProps) {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);
  const sort = searchParams.sort?.toString();

  const filters = Object.fromEntries(
    Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
  );

  const urlSearchParams = new URLSearchParams();
  urlSearchParams.set("filter[integration_type]", "aws_security_hub");
  urlSearchParams.set("page[number]", page.toString());
  urlSearchParams.set("page[size]", pageSize.toString());

  if (sort) {
    urlSearchParams.set("sort", sort);
  }

  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && key !== "filter[integration_type]") {
      const stringValue = Array.isArray(value) ? value[0] : String(value);
      urlSearchParams.set(key, stringValue);
    }
  });

  const [integrations, providers] = await Promise.all([
    getIntegrations(urlSearchParams),
    getProviders({ pageSize: 100 }),
  ]);

  const securityHubIntegrations = integrations?.data || [];
  const availableProviders = providers?.data || [];
  const metadata = integrations?.meta;

  return (
    <ContentLayout title="AWS Security Hub">
      <div className="space-y-6">
        <div className="space-y-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Configure AWS Security Hub integration to automatically send your
            security findings for centralized monitoring and compliance.
          </p>

          <div className="rounded-lg border border-gray-200 bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-800">
            <h3 className="mb-3 text-sm font-semibold text-gray-900 dark:text-gray-100">
              Features:
            </h3>
            <ul className="grid grid-cols-1 gap-2 text-sm text-gray-600 dark:text-gray-300 md:grid-cols-2">
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                Automated findings export
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                Multi-region support
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                Send failed findings only
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                Archive previous findings
              </li>
            </ul>
          </div>
        </div>

        <SecurityHubIntegrationsManager
          integrations={securityHubIntegrations}
          providers={availableProviders}
          metadata={metadata}
        />
      </div>
    </ContentLayout>
  );
}
