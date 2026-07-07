"use client";

import { usePathname } from "next/navigation";

import { useMediaQuery } from "@/hooks/use-media-query";
import { useSidebar } from "@/hooks/use-sidebar";
import { useStore } from "@/hooks/use-store";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";
import { SIDE_PANEL_PUSH_MEDIA_QUERY } from "@/lib/ui-layout";
import { cn } from "@/lib/utils";
import { useSidePanelStore } from "@/store/side-panel";

import { Sidebar } from "../sidebar/sidebar";
export default function MainLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const sidebar = useStore(useSidebar, (x) => x);
  // Push (not overlay): the open side panel shrinks the page by exactly its
  // (user-resizable) width so everything stays reachable. Below `sm` the
  // panel overlays full-width instead, where pushing would leave no page. The
  // full-page chat route has no panel at all.
  const sidePanelOpen = useStore(useSidePanelStore, (x) => x.isOpen);
  const sidePanelWidth = useStore(useSidePanelStore, (x) => x.width);
  const sidePanelResizing = useStore(useSidePanelStore, (x) => x.isResizing);
  const isPushViewport = useMediaQuery(SIDE_PANEL_PUSH_MEDIA_QUERY);
  if (!sidebar) return null;
  const { getOpenState, settings } = sidebar;
  const pushWidth =
    sidePanelOpen &&
    isPushViewport &&
    !pathname?.startsWith(LIGHTHOUSE_ROUTE.CHAT)
      ? sidePanelWidth
      : undefined;
  return (
    <div className="relative flex h-dvh items-center justify-center overflow-hidden">
      {/* Top-left gradient halo */}
      <div
        className="pointer-events-none fixed top-0 left-0 z-0 h-[120%] w-[160%] opacity-[7%] blur-3xl"
        style={{
          background: "linear-gradient(90deg, #31E59F 0%, #60E0EC 100%)",
          transform: "translate(-50%, -50%)",
        }}
      />

      {/* Bottom-right gradient halo */}
      <div
        className="pointer-events-none fixed right-0 bottom-0 z-0 h-[50%] w-[50%] opacity-[7%] blur-3xl"
        style={{
          background: "linear-gradient(90deg, #31E59F 0%, #60E0EC 100%)",
          transform: "translate(50%, 50%)",
        }}
      />

      <Sidebar />
      <main
        // @container: <main> is the reference for the app's (container-query)
        // breakpoints, so pushing it with the side panel re-evaluates them.
        className={cn(
          "no-scrollbar @container relative z-10 mb-auto h-full flex-1 flex-col overflow-y-auto",
          // Margin animates on open/close, but tracks the pointer 1:1 during
          // a drag resize.
          !sidePanelResizing &&
            "transition-[margin-left,margin-right] duration-300 ease-in-out",
          !settings.disabled &&
            (!getOpenState() ? "lg:ml-[90px]" : "lg:ml-[248px]"),
        )}
        style={{ marginRight: pushWidth }}
      >
        {children}
      </main>
    </div>
  );
}
