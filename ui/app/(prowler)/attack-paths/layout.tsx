import { ContentLayout } from "@/components/shadcn/content-layout";

export default function AttackPathsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ContentLayout
      title="Attack Paths"
      icon="lucide:git-branch"
      onboardingAction={{ flowId: "attack-paths" }}
    >
      {children}
    </ContentLayout>
  );
}
