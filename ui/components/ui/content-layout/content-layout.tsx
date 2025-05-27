import { Suspense } from "react";

import { Navbar } from "../nav-bar/navbar";
import { SkeletonContentLayout } from "./skeleton-content-layout";
interface ContentLayoutProps {
  title: string;
  icon: string;
  children: React.ReactNode;
}

export function ContentLayout({ title, icon, children }: ContentLayoutProps) {
  return (
    <>
      <Suspense fallback={<SkeletonContentLayout />}>
        <Navbar title={title} icon={icon} />
      </Suspense>
      <div className="px-6 py-4 sm:px-8 xl:px-10">{children}</div>
    </>
  );
}
