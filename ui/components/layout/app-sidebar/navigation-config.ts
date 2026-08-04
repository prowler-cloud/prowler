import {
  Code,
  CreditCard,
  FileText,
  GitBranch,
  LayoutGrid,
  MessageCircleQuestion,
  Settings,
  ShieldCheck,
  SquareChartGantt,
  Tag,
  Timer,
  Users,
  Warehouse,
} from "lucide-react";

import { LighthouseIcon } from "@/components/icons/Icons";
import { isCloud } from "@/lib/shared/env";
import type { CloudUpgradeFeature } from "@/types/cloud-upgrade";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import type { RolePermissionAttributes } from "@/types/users";

import {
  NAVIGATION_ITEM_KIND,
  NAVIGATION_PERMISSION,
  type NavigationChild,
  type NavigationItem,
  type NavigationSection,
} from "./types";

interface NavigationConfigOptions {
  pathname: string;
  apiDocsUrl?: string | null;
  cloudBillingEnabled?: boolean;
  permissions?: RolePermissionAttributes;
}

interface CloudFeatureOptions {
  isCloudEnvironment: boolean;
  href: string;
  label: string;
  active: boolean;
  feature: CloudUpgradeFeature;
}

function getCloudFeature({
  isCloudEnvironment,
  href,
  label,
  active,
  feature,
}: CloudFeatureOptions): NavigationChild {
  if (!isCloudEnvironment) {
    return {
      kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE,
      label,
      cloudUpgradeFeature: feature,
    };
  }

  return {
    kind: NAVIGATION_ITEM_KIND.LINK,
    href,
    label,
    active,
    highlight: true,
  };
}

function isRouteActive(pathname: string, href: string) {
  return pathname === href || pathname.startsWith(`${href}/`);
}

function hasRequiredPermission(
  item: NavigationItem | NavigationChild,
  permissions?: RolePermissionAttributes,
) {
  return (
    item.requiredPermission === undefined ||
    permissions?.[item.requiredPermission] !== false
  );
}

export function filterNavigationByPermissions(
  sections: NavigationSection[],
  permissions?: RolePermissionAttributes,
) {
  return sections
    .map((section) => ({
      ...section,
      items: section.items
        .filter((item) => hasRequiredPermission(item, permissions))
        .map((item) =>
          item.kind === NAVIGATION_ITEM_KIND.COLLAPSIBLE
            ? {
                ...item,
                children: item.children.filter((child) =>
                  hasRequiredPermission(child, permissions),
                ),
              }
            : item,
        ),
    }))
    .filter((section) => section.items.length > 0);
}

export function getNavigationConfig({
  pathname,
  apiDocsUrl = null,
  cloudBillingEnabled = false,
  permissions,
}: NavigationConfigOptions): NavigationSection[] {
  const isCloudEnvironment = isCloud();
  const apiReferenceUrl = isCloudEnvironment
    ? "https://api.prowler.com/api/v1/docs"
    : apiDocsUrl;

  const sections: NavigationSection[] = [
    {
      items: [
        {
          kind: NAVIGATION_ITEM_KIND.LINK,
          href: "/",
          label: "Overview",
          icon: SquareChartGantt,
          active: pathname === "/",
        },
        ...(!isCloudEnvironment
          ? [
              {
                kind: NAVIGATION_ITEM_KIND.LINK,
                href: "/lighthouse",
                label: "Lighthouse AI",
                icon: LighthouseIcon,
                active:
                  isRouteActive(pathname, "/lighthouse") &&
                  !isRouteActive(pathname, "/lighthouse/settings"),
              } as const,
            ]
          : []),
      ],
    },
    {
      label: "SECURITY",
      items: [
        {
          kind: NAVIGATION_ITEM_KIND.LINK,
          href: "/compliance",
          label: "Compliance",
          icon: ShieldCheck,
          active: isRouteActive(pathname, "/compliance"),
        },
        {
          kind: NAVIGATION_ITEM_KIND.LINK,
          href: "/findings?filter[muted]=false&filter[status__in]=FAIL",
          label: "Findings",
          icon: Tag,
          active: isRouteActive(pathname, "/findings"),
        },
        {
          kind: NAVIGATION_ITEM_KIND.LINK,
          href: "/attack-paths",
          label: "Attack Paths",
          icon: GitBranch,
          active: isRouteActive(pathname, "/attack-paths"),
        },
        {
          kind: NAVIGATION_ITEM_KIND.LINK,
          href: "/scans",
          label: "Scans",
          icon: Timer,
          active:
            isRouteActive(pathname, "/scans") &&
            !isRouteActive(pathname, "/scans/config"),
        },
        {
          kind: NAVIGATION_ITEM_KIND.LINK,
          href: "/resources",
          label: "Resources",
          icon: Warehouse,
          active: isRouteActive(pathname, "/resources"),
        },
      ],
    },
    {
      label: "SETTINGS",
      items: [
        {
          kind: NAVIGATION_ITEM_KIND.COLLAPSIBLE,
          label: "Configuration",
          icon: Settings,
          defaultOpen: true,
          children: [
            {
              kind: NAVIGATION_ITEM_KIND.LINK,
              href: "/providers",
              label: "Providers",
              active: isRouteActive(pathname, "/providers"),
            },
            getCloudFeature({
              isCloudEnvironment,
              href: "/alerts",
              label: "Alerts",
              active: isRouteActive(pathname, "/alerts"),
              feature: CLOUD_UPGRADE_FEATURE.ALERTS,
            }),
            {
              kind: NAVIGATION_ITEM_KIND.LINK,
              href: "/mutelist",
              label: "Mutelist",
              active: pathname === "/mutelist",
            },
            getCloudFeature({
              isCloudEnvironment,
              href: "/scans/config",
              label: "Scans",
              active: isRouteActive(pathname, "/scans/config"),
              feature: CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION,
            }),
            ...(!isCloudEnvironment
              ? [
                  {
                    kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE,
                    label: "CLI Import",
                    cloudUpgradeFeature: CLOUD_UPGRADE_FEATURE.CLI_IMPORT,
                  } as const,
                ]
              : []),
            {
              kind: NAVIGATION_ITEM_KIND.LINK,
              href: "/integrations",
              label: "Integrations",
              requiredPermission: NAVIGATION_PERMISSION.MANAGE_INTEGRATIONS,
              active: isRouteActive(pathname, "/integrations"),
            },
            {
              kind: NAVIGATION_ITEM_KIND.LINK,
              href: "/lighthouse/settings",
              label: "Lighthouse AI",
              active: isRouteActive(pathname, "/lighthouse/settings"),
            },
          ],
        },
        {
          kind: NAVIGATION_ITEM_KIND.COLLAPSIBLE,
          label: "Organization",
          icon: Users,
          defaultOpen: false,
          children: [
            {
              kind: NAVIGATION_ITEM_KIND.LINK,
              href: "/users",
              label: "Users",
              active: isRouteActive(pathname, "/users"),
            },
            {
              kind: NAVIGATION_ITEM_KIND.LINK,
              href: "/invitations",
              label: "Invitations",
              active: isRouteActive(pathname, "/invitations"),
            },
            {
              kind: NAVIGATION_ITEM_KIND.LINK,
              href: "/roles",
              label: "Roles",
              active: isRouteActive(pathname, "/roles"),
            },
          ],
        },
        ...(isCloudEnvironment && cloudBillingEnabled
          ? [
              {
                kind: NAVIGATION_ITEM_KIND.LINK,
                href: "/billing",
                label: "Billing",
                icon: CreditCard,
                requiredPermission: NAVIGATION_PERMISSION.MANAGE_BILLING,
                active: isRouteActive(pathname, "/billing"),
              } as const,
            ]
          : []),
      ],
    },
    {
      label: "HELP",
      items: [
        {
          kind: NAVIGATION_ITEM_KIND.LINK,
          href: "https://docs.prowler.com/",
          label: "Documentation",
          icon: FileText,
          target: "_blank",
        },
        ...(apiReferenceUrl
          ? [
              {
                kind: NAVIGATION_ITEM_KIND.LINK,
                href: apiReferenceUrl,
                label: "API Reference",
                icon: Code,
                target: "_blank",
              } as const,
            ]
          : []),
        {
          kind: NAVIGATION_ITEM_KIND.LINK,
          href: isCloudEnvironment
            ? "https://customer.support.prowler.com/servicedesk/customer/portal/9/create/102"
            : "https://github.com/prowler-cloud/prowler/issues",
          label: isCloudEnvironment ? "Support Desk" : "Community Support",
          icon: MessageCircleQuestion,
          target: "_blank",
        },
        {
          kind: NAVIGATION_ITEM_KIND.LINK,
          href: "https://hub.prowler.com/",
          label: "Prowler Hub",
          icon: LayoutGrid,
          target: "_blank",
          tooltip: "Looking for all available checks? learn more.",
        },
      ],
    },
  ];

  return filterNavigationByPermissions(sections, permissions);
}
