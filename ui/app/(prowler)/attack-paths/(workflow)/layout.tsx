import { Spacer } from "@heroui/spacer";

import { WorkflowAttackPaths } from "@/components/attack-paths/workflow";
import { Navbar } from "@/components/ui/nav-bar/navbar";

/**
 * Workflow layout for Attack Paths wizard
 * Displays the stepper at the top and step content below using full width
 */
export default function AttackPathsWorkflowLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <Navbar title="Attack Path Analysis" icon="" />
      <div className="px-6 py-4 sm:px-8 xl:px-10">
        {/* Stepper - Full Width at Top */}
        <div className="mb-8">
          <WorkflowAttackPaths />
        </div>

        <Spacer y={2} />

        {/* Step Content - Full Width Below */}
        <div>
          {children}
        </div>
      </div>
    </>
  );
}
