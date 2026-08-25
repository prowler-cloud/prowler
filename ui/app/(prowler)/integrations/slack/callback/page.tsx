import { redirect } from "next/navigation";
import { Suspense } from "react";

import { SlackCallback } from "@/components/integrations/slack/slack-callback";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { isCloud } from "@/lib/shared/env";

export default async function SlackCallbackPage() {
  if (!isCloud()) {
    redirect("/");
  }

  return (
    <ContentLayout title="Slack">
      {/* `SlackCallback` reads the query string, so it needs a boundary. */}
      <Suspense fallback={null}>
        <SlackCallback />
      </Suspense>
    </ContentLayout>
  );
}
