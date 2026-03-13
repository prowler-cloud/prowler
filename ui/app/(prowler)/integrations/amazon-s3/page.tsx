import React from "react";

import { getIntegrations } from "@/actions/integrations";
import { getProviders } from "@/actions/providers";
import { S3IntegrationsManager } from "@/components/integrations/s3/s3-integrations-manager";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { ContentLayout } from "@/components/ui";

interface S3IntegrationsProps {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}

export default async function S3Integrations({
  searchParams,
}: S3IntegrationsProps) {
  const resolvedSearchParams = await searchParams;
  const page = parseInt(resolvedSearchParams.page?.toString() || "1", 10);
  const pageSize = parseInt(
    resolvedSearchParams.pageSize?.toString() || "10",
    10,
  );
  const sort = resolvedSearchParams.sort?.toString();

  // Extract all filter parameters
  const filters = Object.fromEntries(
    Object.entries(resolvedSearchParams).filter(([key]) =>
      key.startsWith("filter["),
    ),
  );

  const urlSearchParams = new URLSearchParams();
  urlSearchParams.set("filter[integration_type]", "amazon_s3");
  urlSearchParams.set("page[number]", page.toString());
  urlSearchParams.set("page[size]", pageSize.toString());

  if (sort) {
    urlSearchParams.set("sort", sort);
  }

  // Add any additional filters
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

  const s3Integrations = integrations?.data || [];
  const availableProviders = providers?.data || [];
  const metadata = integrations?.meta;

  return (
    <ContentLayout title="Amazon S3">
      <div className="flex flex-col gap-6">
        <div className="flex flex-col gap-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Configure Amazon S3 integration to automatically export your scan
            results to S3 buckets.
          </p>

          <Card variant="base" padding="lg">
            <CardHeader className="mb-0 pb-3">
              <CardTitle>Features</CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              <ul className="grid grid-cols-1 gap-2 text-sm text-gray-600 md:grid-cols-2 dark:text-gray-300">
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  Automated scan result exports
                </li>
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  Multi-Cloud support
                </li>
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  Configurable export paths
                </li>
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  IAM role and static credentials
                </li>
              </ul>
            </CardContent>
          </Card>
        </div>

        <S3IntegrationsManager
          integrations={s3Integrations}
          providers={availableProviders}
          metadata={metadata}
        />
      </div>
    </ContentLayout>
  );
}
