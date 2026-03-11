import { Navbar } from "@/components/ui/nav-bar/navbar";

/**
 * Layout for Attack Paths
 * Displays content with navbar
 */
export default function AttackPathsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <Navbar title="Attack Paths" icon="" />
      <div className="px-6 py-4 sm:px-8 xl:px-10">
        <div>{children}</div>
      </div>
    </>
  );
}
