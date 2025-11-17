import { Spacer } from "@heroui/spacer";

import { WorkflowAttackPaths } from "@/components/attack-paths/workflow";
import { NavigationHeader } from "@/components/ui";

/**
 * Workflow layout for Attack Paths wizard
 * Displays the steps sidebar and main content area
 */
export default function AttackPathsWorkflowLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <NavigationHeader
        title="Attack Path Analysis"
        icon="icon-park-outline:close-small"
        href="/attack-paths"
      />
      <Spacer y={8} />
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-12">
        {/* Steps Sidebar - Hidden on mobile */}
        <div className="order-1 my-auto hidden h-full lg:col-span-4 lg:col-start-2 lg:block">
          <WorkflowAttackPaths />
        </div>
        {/* Main Content Area */}
        <div className="order-2 my-auto lg:col-span-5 lg:col-start-6">
          {children}
        </div>
      </div>
    </>
  );
}
