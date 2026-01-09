import { getIntegrations } from "@/actions/integrations";
import { SNSIntegrationsManager } from "@/components/integrations/sns/sns-integrations-manager";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { ContentLayout } from "@/components/ui";

interface SNSIntegrationsProps {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}

export default async function SNSIntegrations({
  searchParams,
}: SNSIntegrationsProps) {
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
  urlSearchParams.set("filter[integration_type]", "sns");
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

  const [integrations] = await Promise.all([getIntegrations(urlSearchParams)]);

  const snsIntegrations = integrations?.data || [];
  const metadata = integrations?.meta;

  return (
    <ContentLayout title="Amazon SNS">
      <div className="flex flex-col gap-6">
        <div className="flex flex-col gap-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Configure Amazon SNS integration to send email alerts for security
            findings via SNS topics.
          </p>

          <Card variant="base" padding="lg">
            <CardHeader className="mb-0 pb-3">
              <CardTitle>Features</CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              <ul className="grid grid-cols-1 gap-2 text-sm text-gray-600 md:grid-cols-2 dark:text-gray-300">
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  Email alert notifications
                </li>
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  Multi-Cloud support
                </li>
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  Severity-based filtering
                </li>
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  Region and tag filtering
                </li>
              </ul>
            </CardContent>
          </Card>
        </div>

        <SNSIntegrationsManager
          integrations={snsIntegrations}
          metadata={metadata}
        />
      </div>
    </ContentLayout>
  );
}
