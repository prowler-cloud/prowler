import { ContentLayout } from "@/components/ui";

export default function AttackPathsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ContentLayout title="Attack Paths" icon="lucide:git-branch">
      {children}
    </ContentLayout>
  );
}
