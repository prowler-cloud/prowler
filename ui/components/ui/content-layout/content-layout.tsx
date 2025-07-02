import { ReactNode, Suspense, use } from "react";

import { getUserInfo } from "@/actions/users/users";

import { Navbar } from "../nav-bar/navbar";
import { SkeletonContentLayout } from "./skeleton-content-layout";

interface ContentLayoutProps {
  title: string;
  icon: string | ReactNode;
  children: React.ReactNode;
}

export function ContentLayout({ title, icon, children }: ContentLayoutProps) {
  const user = use(getUserInfo());

  return (
    <>
      <Suspense fallback={<SkeletonContentLayout />}>
        <Navbar title={title} icon={icon} user={user} />
      </Suspense>
      <div className="px-6 py-4 sm:px-8 xl:px-10">{children}</div>
    </>
  );
}
