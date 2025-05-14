import { Suspense, use } from "react";

import { getProfileInfo } from "@/actions/users/users";

import { Navbar } from "../nav-bar/navbar";
import { SkeletonContentLayout } from "./skeleton-content-layout";
interface ContentLayoutProps {
  title: string;
  icon: string;
  children: React.ReactNode;
}

export function ContentLayout({ title, icon, children }: ContentLayoutProps) {
  const user = use(getProfileInfo());

  return (
    <>
      <Suspense fallback={<SkeletonContentLayout />}>
        <Navbar title={title} icon={icon} user={user} />
      </Suspense>
      <div className="px-6 py-4 sm:px-8 xl:px-10">{children}</div>
    </>
  );
}
