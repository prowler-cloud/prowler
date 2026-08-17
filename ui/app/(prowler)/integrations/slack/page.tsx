import { redirect } from "next/navigation";

import { ContentLayout } from "@/components/shadcn/content-layout";
import { isCloud } from "@/lib/shared/env";

import { SlackIntegrationContent } from "./slack-integration-content";

export default async function SlackIntegrationPage() {
  // The Slack API is cloud-only, so self-hosted has nothing behind this page.
  // Mirrors `/alerts`.
  if (!isCloud()) {
    redirect("/");
  }

  return (
    <ContentLayout title="Slack">
      <div className="flex flex-col gap-6">
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Connect a Slack workspace so Prowler can post to one of its channels.
        </p>

        <SlackIntegrationContent />
      </div>
    </ContentLayout>
  );
}
