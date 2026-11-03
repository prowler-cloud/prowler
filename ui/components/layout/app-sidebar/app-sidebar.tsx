import { AppSidebarContent } from "./app-sidebar-content";

interface AppSidebarProps {
  inert?: boolean;
}

export function AppSidebar({ inert }: AppSidebarProps) {
  return (
    <aside
      inert={inert}
      className="bg-bg-neutral-primary fixed inset-y-0 left-0 z-20 hidden w-[248px] overflow-hidden lg:block"
    >
      <AppSidebarContent />
    </aside>
  );
}
