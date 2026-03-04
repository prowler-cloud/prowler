import { Navbar } from "@/components/ui/nav-bar/navbar";

/**
 * Workflow layout for Attack Paths
 * Displays content with navbar
 */
export default function AttackPathsWorkflowLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <Navbar title="Attack Paths Analysis" icon="" />
      <div className="px-6 py-4 sm:px-8 xl:px-10">
        {/* Content */}
        <div>{children}</div>
      </div>
    </>
  );
}
