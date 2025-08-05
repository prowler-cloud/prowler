"use client";

import { Icon } from "@iconify/react";
import { BreadcrumbItem, Breadcrumbs } from "@nextui-org/react";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { ReactNode } from "react";

export interface CustomBreadcrumbItem {
  name: string;
  path?: string;
  icon?: string | ReactNode;
  isLast?: boolean;
  isClickable?: boolean;
  onClick?: () => void;
}

interface BreadcrumbNavigationProps {
  mode?: "auto" | "custom" | "hybrid";
  title?: string;
  icon?: string | ReactNode;
  customItems?: CustomBreadcrumbItem[];
  className?: string;
  paramToPreserve?: string;
  showTitle?: boolean;
}

export function BreadcrumbNavigation({
  mode = "auto",
  title,
  icon,
  customItems = [],
  className = "",
  paramToPreserve = "scanId",
  showTitle = true,
}: BreadcrumbNavigationProps) {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const generateAutoBreadcrumbs = (): CustomBreadcrumbItem[] => {
    const pathIconMapping: Record<string, string> = {
      "/integrations": "lucide:puzzle",
      "/providers": "lucide:cloud",
      "/users": "lucide:users",
      "/compliance": "lucide:shield-check",
      "/findings": "lucide:search",
      "/scans": "lucide:activity",
      "/roles": "lucide:key",
      "/resources": "lucide:database",
      "/lighthouse": "lucide:lightbulb",
      "/manage-groups": "lucide:users-2",
      "/services": "lucide:server",
      "/workloads": "lucide:layers",
    };

    const pathSegments = pathname
      .split("/")
      .filter((segment) => segment !== "");

    if (pathSegments.length === 0) {
      return [{ name: "Home", path: "/", isLast: true }];
    }

    const breadcrumbs: CustomBreadcrumbItem[] = [];
    let currentPath = "";

    pathSegments.forEach((segment, index) => {
      currentPath += `/${segment}`;
      const isLast = index === pathSegments.length - 1;
      let displayName = segment.charAt(0).toUpperCase() + segment.slice(1);

      // Special cases:
      if (segment.includes("-")) {
        displayName = segment
          .split("-")
          .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
          .join(" ");
      }

      const segmentIcon = !isLast ? pathIconMapping[currentPath] : undefined;

      breadcrumbs.push({
        name: displayName,
        path: currentPath,
        icon: segmentIcon,
        isLast,
        isClickable: !isLast,
      });
    });

    return breadcrumbs;
  };

  const buildNavigationUrl = (path: string) => {
    const paramValue = searchParams.get(paramToPreserve);
    if (path === "/compliance" && paramValue) {
      return `/compliance?${paramToPreserve}=${paramValue}`;
    }
    return path;
  };

  const renderTitleWithIcon = (titleText: string, isLink: boolean = false) => (
    <>
      {typeof icon === "string" ? (
        <Icon className="text-default-500" height={24} icon={icon} width={24} />
      ) : icon ? (
        <div className="flex h-8 w-8 items-center justify-center [&>*]:h-full [&>*]:w-full">
          {icon}
        </div>
      ) : null}
      <h1
        className={`text-sm font-bold text-default-700 ${isLink ? "transition-colors hover:text-primary" : ""}`}
      >
        {titleText}
      </h1>
    </>
  );

  // Determine which breadcrumbs to use
  let breadcrumbItems: CustomBreadcrumbItem[] = [];

  switch (mode) {
    case "auto":
      breadcrumbItems = generateAutoBreadcrumbs();
      break;
    case "custom":
      breadcrumbItems = customItems;
      break;
    case "hybrid":
      breadcrumbItems = [...generateAutoBreadcrumbs(), ...customItems];
      break;
  }

  return (
    <div className={className}>
      <Breadcrumbs separator="/">
        {breadcrumbItems.map((breadcrumb, index) => (
          <BreadcrumbItem key={breadcrumb.path || index}>
            {breadcrumb.isLast && showTitle && title ? (
              renderTitleWithIcon(title)
            ) : breadcrumb.isClickable && breadcrumb.path ? (
              <Link
                href={buildNavigationUrl(breadcrumb.path)}
                className="flex cursor-pointer items-center space-x-2"
              >
                {breadcrumb.icon && typeof breadcrumb.icon === "string" ? (
                  <Icon
                    className="text-default-500"
                    height={24}
                    icon={breadcrumb.icon}
                    width={24}
                  />
                ) : breadcrumb.icon ? (
                  <div className="flex h-6 w-6 items-center justify-center [&>*]:h-full [&>*]:w-full">
                    {breadcrumb.icon}
                  </div>
                ) : null}
                <span className="text-wrap text-sm font-bold text-default-700 transition-colors hover:text-primary">
                  {breadcrumb.name}
                </span>
              </Link>
            ) : breadcrumb.isClickable && breadcrumb.onClick ? (
              <button
                onClick={breadcrumb.onClick}
                className="flex cursor-pointer items-center space-x-2 text-wrap text-sm font-medium text-primary transition-colors hover:text-primary-600"
              >
                {breadcrumb.icon && typeof breadcrumb.icon === "string" ? (
                  <Icon
                    className="text-default-500"
                    height={24}
                    icon={breadcrumb.icon}
                    width={24}
                  />
                ) : breadcrumb.icon ? (
                  <div className="flex h-6 w-6 items-center justify-center [&>*]:h-full [&>*]:w-full">
                    {breadcrumb.icon}
                  </div>
                ) : null}
                <span>{breadcrumb.name}</span>
              </button>
            ) : (
              <div className="flex items-center space-x-2">
                {breadcrumb.icon && typeof breadcrumb.icon === "string" ? (
                  <Icon
                    className="text-default-500"
                    height={24}
                    icon={breadcrumb.icon}
                    width={24}
                  />
                ) : breadcrumb.icon ? (
                  <div className="flex h-6 w-6 items-center justify-center [&>*]:h-full [&>*]:w-full">
                    {breadcrumb.icon}
                  </div>
                ) : null}
                <span className="text-wrap text-sm font-medium text-gray-900 dark:text-gray-100">
                  {breadcrumb.name}
                </span>
              </div>
            )}
          </BreadcrumbItem>
        ))}
      </Breadcrumbs>
    </div>
  );
}
