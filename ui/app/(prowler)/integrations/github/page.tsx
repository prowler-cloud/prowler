import { getIntegrations } from "@/actions/integrations";
import { GitHubIntegrationsManager } from "@/components/integrations/github/github-integrations-manager";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { ContentLayout } from "@/components/ui";

interface GitHubIntegrationsProps {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}

export default async function GitHubIntegrations({
  searchParams,
}: GitHubIntegrationsProps) {
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
  urlSearchParams.set("filter[integration_type]", "github");
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

  const githubIntegrations = integrations?.data || [];
  const metadata = integrations?.meta;

  return (
    <ContentLayout title="GitHub">
      <div className="flex flex-col gap-6">
        <div className="flex flex-col gap-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Configure GitHub integration to automatically create issues for
            security findings in your GitHub repositories.
          </p>

          <Card variant="base" padding="lg">
            <CardHeader className="mb-0 pb-3">
              <CardTitle>Features</CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              <ul className="grid grid-cols-1 gap-2 text-sm text-gray-600 md:grid-cols-2 dark:text-gray-300">
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  Automated issue creation
                </li>
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  Multi-Cloud support
                </li>
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  Repository-based tracking
                </li>
                <li className="flex items-center gap-2">
                  <span className="bg-button-primary h-1.5 w-1.5 rounded-full" />
                  Label customization
                </li>
              </ul>
            </CardContent>
          </Card>
        </div>

        <GitHubIntegrationsManager
          integrations={githubIntegrations}
          metadata={metadata}
        />
      </div>
    </ContentLayout>
  );
}
