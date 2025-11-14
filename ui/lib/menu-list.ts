import {
  CloudCog,
  Cog,
  Group,
  Mail,
  MessageCircleQuestion,
  Puzzle,
  Settings,
  ShieldCheck,
  SquareChartGantt,
  Tag,
  Timer,
  User,
  UserCog,
  Users,
  VolumeX,
  Warehouse,
} from "lucide-react";
import type { MouseEvent } from "react";

import { ProwlerShort } from "@/components/icons";
import {
  APIdocIcon,
  DocIcon,
  GithubIcon,
  LighthouseIcon,
  SupportIcon,
} from "@/components/icons/Icons";
import { GroupProps } from "@/types";

interface MenuListOptions {
  pathname: string;
  hasProviders?: boolean;
  openMutelistModal?: () => void;
  requestMutelistModalOpen?: () => void;
}

export const getMenuList = ({
  pathname,
  hasProviders,
  openMutelistModal,
  requestMutelistModalOpen,
}: MenuListOptions): GroupProps[] => {
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
    {
      groupLabel: "",
      menus: [
        {
          href: "/findings",
          label: "Findings",
          icon: Tag,
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
            { href: "/providers", label: "Cloud Providers", icon: CloudCog },
            {
              href: "/providers",
              label: "Mutelist",
              icon: VolumeX,
              disabled: hasProviders === false,
              active: false,
              onClick: (event: MouseEvent<HTMLAnchorElement>) => {
                if (hasProviders === false) {
                  event.preventDefault();
                  event.stopPropagation();
                  return;
                }

                requestMutelistModalOpen?.();

                if (pathname !== "/providers") {
                  return;
                }

                event.preventDefault();
                event.stopPropagation();
                openMutelistModal?.();
              },
            },
            { href: "/manage-groups", label: "Provider Groups", icon: Group },
            { href: "/scans", label: "Scan Jobs", icon: Timer },
            { href: "/integrations", label: "Integrations", icon: Puzzle },
            { href: "/roles", label: "Roles", icon: UserCog },
            { href: "/lighthouse/config", label: "Lighthouse AI", icon: Cog },
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
              href:
                process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true"
                  ? "https://api.prowler.com/api/v1/docs"
                  : `${process.env.NEXT_PUBLIC_API_DOCS_URL}`,
              target: "_blank",
              label: "API reference",
              icon: APIdocIcon,
            },
            {
              href: "https://customer.support.prowler.com/servicedesk/customer/portal/9/create/102",
              target: "_blank",
              label: "Customer Support",
              icon: MessageCircleQuestion,
            },
            {
              href: "https://github.com/prowler-cloud/prowler/issues",
              target: "_blank",
              label: "Community Support",
              icon: GithubIcon,
            },
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
          // tooltip: "Looking for all available checks? learn more.",
        },
      ],
    },
  ];
};
