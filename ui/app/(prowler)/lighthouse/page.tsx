import { redirect } from "next/navigation";

import { getLighthouseConfig } from "@/actions/lighthouse/lighthouse";
import { LighthouseIcon } from "@/components/icons/Icons";
import { Chat } from "@/components/lighthouse";
import { ContentLayout } from "@/components/ui";

export default async function AIChatbot() {
  const lighthouseConfig = await getLighthouseConfig();

  const hasConfig = !!lighthouseConfig;

  if (!hasConfig) {
    return redirect("/lighthouse/config");
  }

  const isActive = lighthouseConfig.is_active ?? false;

  return (
    <ContentLayout title="Lighthouse AI" icon={<LighthouseIcon />}>
      <Chat hasConfig={hasConfig} isActive={isActive} />
    </ContentLayout>
  );
}
