"use client";

import { Icon } from "@iconify/react";
import { BreadcrumbItem, Breadcrumbs } from "@nextui-org/react";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { ReactNode } from "react";

import { ThemeSwitch } from "@/components/ThemeSwitch";
import { UserProfileProps } from "@/types";

import { SheetMenu } from "../sidebar/sheet-menu";
import { UserNav } from "../user-nav/user-nav";

interface NavbarProps {
  title: string;
  icon: string | ReactNode;
  user: UserProfileProps;
}

interface BreadcrumbItem {
  name: string;
  path: string;
  isLast: boolean;
}

export function Navbar({ title, icon, user }: NavbarProps) {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const generateBreadcrumbs = (): BreadcrumbItem[] => {
    const pathSegments = pathname
      .split("/")
      .filter((segment) => segment !== "");

    //if home, no show breadcrumbs
    if (pathSegments.length === 0) {
      return [];
    }

    const breadcrumbs: BreadcrumbItem[] = [];
    let currentPath = "";

    pathSegments.forEach((segment, index) => {
      currentPath += `/${segment}`;
      const isLast = index === pathSegments.length - 1;
      let displayName = segment.charAt(0).toUpperCase() + segment.slice(1);

      //special cases:
      if (segment.includes("-")) {
        displayName = segment
          .split("-")
          .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
          .join(" ");
      }

      breadcrumbs.push({
        name: displayName,
        path: currentPath,
        isLast,
      });
    });

    return breadcrumbs;
  };

  const buildNavigationUrl = (paramToPreserve: string, path: string) => {
    const paramValue = searchParams.get(paramToPreserve);
    if (path === "/compliance" && paramValue) {
      return `/compliance?${paramToPreserve}=${paramValue}`;
    }

    return path;
  };

  const breadcrumbs = generateBreadcrumbs();

  return (
    <header className="sticky top-0 z-10 w-full bg-background/95 shadow backdrop-blur supports-[backdrop-filter]:bg-background/60 dark:shadow-primary">
      <div className="mx-4 flex h-14 items-center sm:mx-8">
        <div className="flex items-center space-x-2">
          <SheetMenu />

          {breadcrumbs.length > 0 && (
            <Breadcrumbs separator="/">
              {breadcrumbs.map((breadcrumb) => (
                <BreadcrumbItem key={breadcrumb.path}>
                  {breadcrumb.isLast ? (
                    <>
                      {typeof icon === "string" ? (
                        <Icon
                          className="text-default-500"
                          height={24}
                          icon={icon}
                          width={24}
                        />
                      ) : (
                        <div className="flex h-8 w-8 items-center justify-center [&>*]:h-full [&>*]:w-full">
                          {icon}
                        </div>
                      )}
                      <span className="text-sm font-bold text-default-700">
                        {title}
                      </span>
                    </>
                  ) : (
                    <Link
                      href={buildNavigationUrl("scanId", breadcrumb.path)}
                      className="cursor-pointer text-sm font-bold text-default-700 transition-colors hover:text-primary"
                    >
                      {breadcrumb.name}
                    </Link>
                  )}
                </BreadcrumbItem>
              ))}
            </Breadcrumbs>
          )}
        </div>
        <div className="flex flex-1 items-center justify-end gap-3">
          <ThemeSwitch />
          <UserNav user={user} />
        </div>
      </div>
    </header>
  );
}
