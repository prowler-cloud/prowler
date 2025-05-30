"use client";

import { usePathname } from "next/navigation";

import { useSidebar } from "@/hooks/use-sidebar";
import { useStore } from "@/hooks/use-store";
import { cn } from "@/lib/utils";

import { Navbar } from "../nav-bar/navbar";
import { Sidebar } from "../sidebar/sidebar";

// Page metadata mapping
const PAGE_METADATA = [
  {
    path: "/",
    title: "Overview",
    icon: "solar:pie-chart-2-outline",
  },
  {
    path: "/compliance",
    title: "Compliance",
    icon: "fluent-mdl2:compliance-audit",
  },
  {
    path: "/findings",
    title: "Findings",
    icon: "carbon:data-view-alt",
  },
  {
    path: "/scans",
    title: "Scans",
    icon: "lucide:scan-search",
  },
  {
    path: "/providers",
    title: "Cloud Providers",
    icon: "fluent:cloud-sync-24-regular",
  },
  {
    path: "/services",
    title: "Services",
    icon: "material-symbols:linked-services-outline",
  },
  {
    path: "/workloads",
    title: "Workloads",
    icon: "lucide:tags",
  },
  {
    path: "/integrations",
    title: "Integrations",
    icon: "tabler:puzzle",
  },
  {
    path: "/users",
    title: "Users",
    icon: "ci:users",
  },
  {
    path: "/roles",
    title: "Roles",
    icon: "mdi:account-key-outline",
  },
  {
    path: "/invitations",
    title: "Invitations",
    icon: "ci:users",
  },
  {
    path: "/manage-groups",
    title: "Manage Groups",
    icon: "solar:users-group-two-rounded-outline",
  },
  {
    path: "/profile",
    title: "User Profile",
    icon: "ci:users",
  },
] as const;

export default function MainLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const sidebar = useStore(useSidebar, (x) => x);
  const pathname = usePathname();

  if (!sidebar) return null;

  const { getOpenState, settings } = sidebar;

  // Get page metadata from pathname
  const pageData = PAGE_METADATA.find((page) => page.path === pathname) || {
    title: "Page",
    icon: "solar:document-outline",
  };

  return (
    <div className="flex h-dvh items-center justify-center overflow-hidden">
      <Sidebar />
      <main
        className={cn(
          "no-scrollbar mb-auto h-full flex-1 flex-col overflow-y-auto transition-[margin-left] duration-300 ease-in-out",
          !settings.disabled && (!getOpenState() ? "lg:ml-[90px]" : "lg:ml-72"),
        )}
      >
        <Navbar title={pageData.title} icon={pageData.icon} />
        <div className="px-6 py-4 sm:px-8 xl:px-10">{children}</div>
      </main>
    </div>
  );
}
