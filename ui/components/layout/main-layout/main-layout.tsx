"use client";

import { AppSidebar } from "@/components/layout/app-sidebar";
import { CloudUpgradeModal } from "@/components/shared/cloud-upgrade-modal";

export default function MainLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="relative flex h-dvh items-center justify-center overflow-hidden">
      <AppSidebar />
      <CloudUpgradeModal />
      <main className="no-scrollbar relative z-10 mb-auto ml-4 h-full flex-1 flex-col overflow-y-auto lg:ml-[280px]">
        {children}
      </main>
    </div>
  );
}
