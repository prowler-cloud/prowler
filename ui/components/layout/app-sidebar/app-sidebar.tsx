import { AppSidebarContent } from "./app-sidebar-content";

export function AppSidebar() {
  return (
    <aside className="border-border-neutral-secondary bg-bg-neutral-primary fixed inset-y-0 left-0 z-20 hidden w-[264px] overflow-hidden border-r lg:block">
      <div aria-hidden="true" className="app-sidebar-halo" />
      <AppSidebarContent />
    </aside>
  );
}
