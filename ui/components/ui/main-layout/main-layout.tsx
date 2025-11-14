"use client";

import { useSidebar } from "@/hooks/use-sidebar";
import { useStore } from "@/hooks/use-store";
import { cn } from "@/lib/utils";

import { Sidebar } from "../sidebar/sidebar";
export default function MainLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const sidebar = useStore(useSidebar, (x) => x);
  if (!sidebar) return null;
  const { getOpenState, settings } = sidebar;
  return (
    <div className="relative flex h-dvh items-center justify-center overflow-hidden">
      {/* Top-left gradient halo */}
      <div
        className="pointer-events-none fixed top-0 left-0 z-0 size-[600px] opacity-20 blur-3xl"
        style={{
          background: "linear-gradient(90deg, #31E59F 0%, #60E0EC 100%)",
          transform: "translate(-50%, -50%)",
        }}
      />

      {/* Bottom-right gradient halo */}
      <div
        className="pointer-events-none fixed right-0 bottom-0 z-0 size-[600px] opacity-20 blur-3xl"
        style={{
          background: "linear-gradient(90deg, #31E59F 0%, #60E0EC 100%)",
          transform: "translate(50%, 50%)",
        }}
      />

      <Sidebar />
      <main
        className={cn(
          "no-scrollbar relative z-10 mb-auto h-full flex-1 flex-col overflow-y-auto transition-[margin-left] duration-300 ease-in-out",
          !settings.disabled && (!getOpenState() ? "lg:ml-[90px]" : "lg:ml-72"),
        )}
      >
        {children}
      </main>
    </div>
  );
}
