import { redirect } from "next/navigation";

import { isLighthouseConfigured } from "@/actions/lighthouse/lighthouse";
import { LighthouseIcon } from "@/components/icons/Icons";
import { Chat } from "@/components/lighthouse";
import { ContentLayout } from "@/components/ui";

export default async function AIChatbot() {
  const hasConfig = await isLighthouseConfigured();

  if (!hasConfig) {
    return redirect("/lighthouse/config");
  }

  // If properly configured, we can assume it's active
  const isActive = true;

  return (
    <ContentLayout title="Lighthouse AI" icon={<LighthouseIcon />}>
      <Chat hasConfig={hasConfig} isActive={isActive} />
    </ContentLayout>
  );
}
