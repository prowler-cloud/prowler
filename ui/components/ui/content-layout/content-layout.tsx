"use client";

import { ReactNode } from "react";

import { Navbar } from "../nav-bar/navbar";

interface ContentLayoutProps {
  title: string;
  icon: string | ReactNode;
  children: React.ReactNode;
}

export function ContentLayout({ title, icon, children }: ContentLayoutProps) {
  return (
    <>
      <Navbar title={title} icon={icon} />
      <div className="px-6 py-4 sm:px-8 xl:px-10">{children}</div>
    </>
  );
}
