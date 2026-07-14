import { ExternalLink, KeyRound, Terminal, Upload } from "lucide-react";
import { redirect } from "next/navigation";

import { Button } from "@/components/shadcn/button/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn/card/card";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { DOCS_URLS } from "@/lib/external-urls";
import { isCloud } from "@/lib/shared/env";

const CLI_COMMANDS = [
  'export PROWLER_CLOUD_API_KEY="pk_your_api_key_here"',
  "prowler aws --push-to-cloud",
] as const;

export default function CliImportPage() {
  if (!isCloud()) {
    redirect("/");
  }

  return (
    <ContentLayout
      title="Import findings from Prowler CLI"
      icon="lucide:upload"
    >
      <div className="mx-auto flex w-full max-w-3xl flex-col gap-6">
        <p className="text-text-neutral-secondary text-sm">
          Send scan results from Prowler CLI to this Prowler Cloud tenant for
          centralized analysis, history, and collaboration.
        </p>

        <Card variant="inner" padding="lg">
          <CardHeader>
            <div className="flex items-center gap-3">
              <KeyRound aria-hidden="true" className="size-5" />
              <CardTitle>1. Create an API key</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-text-neutral-secondary text-sm">
              Use a Prowler Cloud API key with the Manage Ingestions permission,
              then expose it to the CLI through the PROWLER_CLOUD_API_KEY
              environment variable.
            </p>
          </CardContent>
        </Card>

        <Card variant="inner" padding="lg">
          <CardHeader>
            <div className="flex items-center gap-3">
              <Terminal aria-hidden="true" className="size-5" />
              <CardTitle>2. Run a scan with Cloud upload</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <pre className="border-border-neutral-secondary bg-bg-neutral-primary overflow-x-auto rounded-lg border p-4 text-sm">
              <code>{CLI_COMMANDS.join("\n\n")}</code>
            </pre>
            <p className="text-text-neutral-secondary text-sm">
              Replace aws with the provider you want to scan. The
              --push-to-cloud flag uploads the results after the scan completes.
            </p>
          </CardContent>
        </Card>

        <Card variant="inner" padding="lg">
          <CardHeader>
            <div className="flex items-center gap-3">
              <Upload aria-hidden="true" className="size-5" />
              <CardTitle>3. Review imported findings</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-text-neutral-secondary text-sm">
              Imported findings appear in Prowler Cloud alongside managed scan
              results so your team can review them from one place.
            </p>
            <Button asChild variant="outline">
              <a
                href={DOCS_URLS.FINDINGS_INGESTION}
                target="_blank"
                rel="noopener noreferrer"
              >
                Read the full CLI import guide
                <ExternalLink aria-hidden="true" className="size-4" />
              </a>
            </Button>
          </CardContent>
        </Card>
      </div>
    </ContentLayout>
  );
}
