import { GitBranch } from "lucide-react";

import { ContentLayout } from "@/components/shadcn/content-layout";

export default function AttackPathsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ContentLayout
      title="Attack Paths"
      icon={<GitBranch />}
      onboardingAction={{ flowId: "attack-paths" }}
    >
      {children}
    </ContentLayout>
  );
}
