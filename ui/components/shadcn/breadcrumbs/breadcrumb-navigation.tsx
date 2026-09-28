"use client";

import {
  BellRing,
  Cloud,
  Database,
  GitBranch,
  Key,
  Layers,
  Puzzle,
  Search,
  Server,
  ShieldCheck,
  Timer,
  Users,
  UsersRound,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import type { ReactElement, ReactNode } from "react";

import { LighthouseIcon } from "@/components/icons/Icons";
import { buildPerScanComplianceHref } from "@/lib/compliance/compliance-tab-url";
import { cn } from "@/lib/utils";

export interface CustomBreadcrumbItem {
  name: string;
  path?: string;
  icon?: ReactElement;
  isLast?: boolean;
  isClickable?: boolean;
  onClick?: () => void;
}

interface BreadcrumbNavigationProps {
  mode?: "auto" | "custom" | "hybrid";
  title?: string;
  icon?: ReactElement;
  titleAction?: ReactNode;
  customItems?: CustomBreadcrumbItem[];
  className?: string;
  paramToPreserve?: string;
  showTitle?: boolean;
}

export function BreadcrumbNavigation({
  mode = "auto",
  title,
  icon,
  titleAction,
  customItems = [],
  className = "",
  paramToPreserve = "scanId",
  showTitle = true,
}: BreadcrumbNavigationProps) {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const generateAutoBreadcrumbs = (): CustomBreadcrumbItem[] => {
    const pathIconMapping: Record<string, ReactElement> = {
      "/integrations": <Puzzle />,
      "/alerts": <BellRing />,
      "/providers": <Cloud />,
      "/users": <Users />,
      "/compliance": <ShieldCheck />,
      "/findings": <Search />,
      "/scans": <Timer />,
      "/roles": <Key />,
      "/resources": <Database />,
      "/lighthouse": <LighthouseIcon />,
      "/manage-groups": <UsersRound />,
      "/services": <Server />,
      "/workloads": <Layers />,
      "/attack-paths": <GitBranch />,
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

      if (segment.includes("-")) {
        displayName = segment
          .split("-")
          .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
          .join(" ");
      }
      if (segment === "lighthouse") {
        displayName = "Lighthouse AI";
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
    // A preserved scan only makes sense on Single Scan, which is no longer
    // the landing tab: the bare route would drop it for Multiple Scans.
    if (path === "/compliance" && paramValue) {
      return buildPerScanComplianceHref({ [paramToPreserve]: paramValue });
    }
    return path;
  };

  const renderTitleWithIcon = (
    titleText: string,
    isLink: boolean = false,
    showIcon: boolean = true,
  ) => (
    <div className="flex items-center gap-2">
      {showIcon && icon ? (
        <div className="text-text-neutral-primary flex shrink-0 items-center justify-center">
          {icon}
        </div>
      ) : null}
      <h1
        className={`text-text-neutral-primary max-w-[200px] truncate text-sm font-bold sm:max-w-none ${isLink ? "hover:text-button-primary transition-colors" : ""}`}
      >
        {titleText}
      </h1>
      {titleAction}
    </div>
  );

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
    <div className={cn(className, "w-fit md:w-full")}>
      <nav aria-label="Breadcrumb">
        <ol className="flex flex-wrap items-center">
          {breadcrumbItems.map((breadcrumb, index) => (
            <li
              key={breadcrumb.path || index}
              className="flex items-center"
              aria-current={
                index === breadcrumbItems.length - 1 ? "page" : undefined
              }
            >
              {breadcrumb.isLast && showTitle && title ? (
                renderTitleWithIcon(title, false, index === 0)
              ) : breadcrumb.isClickable && breadcrumb.path ? (
                <Link
                  href={buildNavigationUrl(breadcrumb.path)}
                  className="flex cursor-pointer items-center gap-2"
                >
                  {index === 0 && breadcrumb.icon ? (
                    <BreadcrumbIcon className="text-text-neutral-primary">
                      {breadcrumb.icon}
                    </BreadcrumbIcon>
                  ) : null}
                  <span className="text-text-neutral-primary hover:text-button-primary max-w-[150px] truncate text-sm font-bold transition-colors sm:max-w-none">
                    {breadcrumb.name}
                  </span>
                </Link>
              ) : breadcrumb.isClickable && breadcrumb.onClick ? (
                <button
                  onClick={breadcrumb.onClick}
                  className="text-text-neutral-primary hover:text-text-neutral-primary-hover flex cursor-pointer items-center gap-2 text-sm font-medium transition-colors"
                >
                  {index === 0 && breadcrumb.icon ? (
                    <BreadcrumbIcon className="text-text-neutral-primary">
                      {breadcrumb.icon}
                    </BreadcrumbIcon>
                  ) : null}
                  <span className="max-w-[150px] truncate sm:max-w-none">
                    {breadcrumb.name}
                  </span>
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  {index === 0 && breadcrumb.icon ? (
                    <BreadcrumbIcon className="text-text-neutral-tertiary">
                      {breadcrumb.icon}
                    </BreadcrumbIcon>
                  ) : null}
                  <span className="max-w-[150px] truncate text-sm font-medium text-gray-900 sm:max-w-none dark:text-gray-100">
                    {breadcrumb.name}
                  </span>
                </div>
              )}
              {index < breadcrumbItems.length - 1 && (
                <span
                  aria-hidden="true"
                  className="text-text-neutral-tertiary px-1 text-sm"
                >
                  /
                </span>
              )}
            </li>
          ))}
        </ol>
      </nav>
    </div>
  );
}

function BreadcrumbIcon({
  children,
  className,
}: {
  children: ReactNode;
  className: string;
}) {
  return (
    <div
      aria-hidden="true"
      className={cn(
        "flex h-6 w-6 items-center justify-center *:h-full *:w-full",
        className,
      )}
    >
      {children}
    </div>
  );
}
