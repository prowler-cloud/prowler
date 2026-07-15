import {
  BellRing,
  CloudCog,
  Cog,
  GitBranch,
  Mail,
  MessageCircleQuestion,
  Puzzle,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  SquareChartGantt,
  Tag,
  Timer,
  Upload,
  User,
  UserCog,
  Users,
  VolumeX,
  Warehouse,
} from "lucide-react";

import { ProwlerShort } from "@/components/icons";
import {
  APIdocIcon,
  DocIcon,
  GithubIcon,
  LighthouseIcon,
  SupportIcon,
} from "@/components/icons/Icons";
import { isCloud } from "@/lib/shared/env";
import {
  type CloudUpgradeFeature,
  type GroupProps,
  type IconComponent,
  SUBMENU_KIND,
  type SubmenuProps,
} from "@/types";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

interface MenuListOptions {
  pathname: string;
  // Passed in (not read here) so the island isn't read during SSR — that would
  // cause a hydration mismatch. See useRuntimeConfig.
  apiDocsUrl?: string | null;
}

interface CloudFeatureSubmenuOptions {
  isCloudEnvironment: boolean;
  href: string;
  label: string;
  icon: IconComponent;
  active: boolean;
  feature: CloudUpgradeFeature;
}

const getCloudFeatureSubmenu = ({
  isCloudEnvironment,
  href,
  label,
  icon,
  active,
  feature,
}: CloudFeatureSubmenuOptions): SubmenuProps => {
  if (!isCloudEnvironment) {
    return {
      kind: SUBMENU_KIND.CLOUD_UPGRADE,
      label,
      icon,
      cloudUpgradeFeature: feature,
    };
  }

  return {
    kind: SUBMENU_KIND.LINK,
    href,
    label,
    icon,
    active,
    highlight: true,
  };
};

export const getMenuList = ({
  pathname,
  apiDocsUrl = null,
}: MenuListOptions): GroupProps[] => {
  const isCloudEnv = isCloud();

  return [
    {
      groupLabel: "",
      menus: [
        {
          href: "/",
          label: "Overview",
          icon: SquareChartGantt,
          active: pathname === "/",
        },
      ],
    },
    {
      groupLabel: "",
      menus: [
        {
          href: "/compliance",
          label: "Compliance",
          icon: ShieldCheck,
          active: pathname === "/compliance",
        },
      ],
    },
    ...(isCloudEnv
      ? []
      : [
          {
            groupLabel: "",
            menus: [
              {
                href: "/lighthouse",
                label: "Lighthouse AI",
                icon: LighthouseIcon,
                active: pathname === "/lighthouse",
              },
            ],
          },
        ]),
    {
      groupLabel: "",
      menus: [
        {
          href: "/attack-paths",
          label: "Attack Paths",
          icon: GitBranch,
          active: pathname.startsWith("/attack-paths"),
        },
      ],
    },

    {
      groupLabel: "",
      menus: [
        {
          href: "/findings?filter[muted]=false&filter[status__in]=FAIL",
          label: "Findings",
          icon: Tag,
        },
      ],
    },
    {
      groupLabel: "",
      menus: [
        {
          href: "/scans",
          label: "Scans",
          icon: Timer,
          // Exact match so it isn't also marked active on the `/scans/config`
          // sub-route (mirrors the top-level Lighthouse entry).
          active: pathname === "/scans",
        },
      ],
    },
    {
      groupLabel: "",
      menus: [
        {
          href: "/resources",
          label: "Resources",
          icon: Warehouse,
        },
      ],
    },
    {
      groupLabel: "",
      menus: [
        {
          href: "",
          label: "Configuration",
          icon: Settings,
          submenus: [
            { href: "/providers", label: "Providers", icon: CloudCog },
            getCloudFeatureSubmenu({
              isCloudEnvironment: isCloudEnv,
              href: "/alerts",
              label: "Alerts",
              icon: BellRing,
              active: pathname.startsWith("/alerts"),
              feature: CLOUD_UPGRADE_FEATURE.ALERTS,
            }),
            {
              href: "/mutelist",
              label: "Mutelist",
              icon: VolumeX,
              active: pathname === "/mutelist",
            },
            getCloudFeatureSubmenu({
              isCloudEnvironment: isCloudEnv,
              href: "/scans/config",
              label: "Scan",
              icon: SlidersHorizontal,
              active: pathname.startsWith("/scans/config"),
              feature: CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION,
            }),
            ...(!isCloudEnv
              ? [
                  {
                    kind: SUBMENU_KIND.CLOUD_UPGRADE,
                    label: "CLI Import",
                    icon: Upload,
                    cloudUpgradeFeature: CLOUD_UPGRADE_FEATURE.CLI_IMPORT,
                  },
                ]
              : []),
            { href: "/integrations", label: "Integrations", icon: Puzzle },
            { href: "/lighthouse/settings", label: "Lighthouse AI", icon: Cog },
          ],
          defaultOpen: true,
        },
      ],
    },
    {
      groupLabel: "",
      menus: [
        {
          href: "",
          label: "Organization",
          icon: Users,
          submenus: [
            { href: "/users", label: "Users", icon: User },
            { href: "/invitations", label: "Invitations", icon: Mail },
            { href: "/roles", label: "Roles", icon: UserCog },
          ],
          defaultOpen: false,
        },
      ],
    },
    {
      groupLabel: "",
      menus: [
        {
          href: "",
          label: "Support & Help",
          icon: SupportIcon,
          submenus: [
            {
              href: "https://docs.prowler.com/",
              target: "_blank",
              label: "Documentation",
              icon: DocIcon,
            },
            {
              href: isCloudEnv
                ? "https://api.prowler.com/api/v1/docs"
                : (apiDocsUrl ?? ""),
              target: "_blank",
              label: "API reference",
              icon: APIdocIcon,
            },
            ...(isCloudEnv
              ? [
                  {
                    href: "https://customer.support.prowler.com/servicedesk/customer/portal/9/create/102",
                    target: "_blank",
                    label: "Support Desk",
                    icon: MessageCircleQuestion,
                  },
                ]
              : [
                  {
                    href: "https://github.com/prowler-cloud/prowler/issues",
                    target: "_blank",
                    label: "Community Support",
                    icon: GithubIcon,
                  },
                ]),
          ],
          defaultOpen: false,
        },
      ],
    },
    {
      groupLabel: "",
      menus: [
        {
          href: "https://hub.prowler.com/",
          label: "Prowler Hub",
          icon: ProwlerShort,
          target: "_blank",
          tooltip: "Looking for all available checks? learn more.",
        },
      ],
    },
  ];
};
