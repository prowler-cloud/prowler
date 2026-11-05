import { type ReactElement } from "react";

import { Navbar } from "@/components/layout/nav-bar/navbar";

interface ContentLayoutProps {
  title: string;
  icon?: ReactElement;
  children: React.ReactNode;
}

export function ContentLayout({ title, icon, children }: ContentLayoutProps) {
  return (
    <>
      <Navbar title={title} icon={icon} />
      <div className="py-4 pr-6">{children}</div>
    </>
  );
}
