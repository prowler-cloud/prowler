import {
  CloudCog,
  Cog,
  Group,
  Mail,
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
import { LighthouseIcon } from "@/components/icons/Icons";
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
          label: "Cignify AI",
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

                if (pathname !== "/providers") return;

                event.preventDefault();
                event.stopPropagation();
                openMutelistModal?.();
              },
            },
            { href: "/manage-groups", label: "Provider Groups", icon: Group },
            { href: "/scans", label: "Scan Jobs", icon: Timer },
            { href: "/integrations", label: "Integrations", icon: Puzzle },
            { href: "/roles", label: "Roles", icon: UserCog },
            { href: "/lighthouse/config", label: "Cignify AI", icon: Cog },
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

    // ✅ Renamed Hub
    {
      groupLabel: "",
      menus: [
        {
          href: "https://hub.prowler.com/",
          label: "Cignify Hub",
          icon: ProwlerShort,
          target: "_blank",
          tooltip: "Looking for all available checks? Learn more.",
        },
      ],
    },
  ];
};
