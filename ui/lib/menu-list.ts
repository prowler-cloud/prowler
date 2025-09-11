"use client";

import {
  Bookmark,
  CloudCog,
  Cog,
  Group,
  LayoutGrid,
  Mail,
  Puzzle,
  Settings,
  ShieldCheck,
  SquareChartGantt,
  SquarePen,
  Tag,
  Timer,
  User,
  UserCog,
  Users,
  VolumeX,
  Warehouse,
} from "lucide-react";

import { ProwlerShort } from "@/components/icons";
import {
  APIdocIcon,
  AWSIcon,
  AzureIcon,
  CircleHelpIcon,
  DocIcon,
  GCPIcon,
  GithubIcon,
  KubernetesIcon,
  LighthouseIcon,
  M365Icon,
  SupportIcon,
} from "@/components/icons/Icons";
import { GroupProps } from "@/types";

interface MenuListOptions {
  pathname: string;
  hasProviders?: boolean;
  openMutelistModal?: () => void;
}

export const getMenuList = ({
  pathname,
  hasProviders,
  openMutelistModal,
}: MenuListOptions): GroupProps[] => {
  return [
    {
      groupLabel: "",
      menus: [
        {
          href: "",
          label: "Analytics",
          icon: LayoutGrid,
          submenus: [
            {
              href: "/",
              label: "Overview",
              icon: SquareChartGantt,
              active: pathname === "/",
            },
            {
              href: "/compliance",
              label: "Compliance",
              icon: ShieldCheck,
              active: pathname === "/compliance",
            },
          ],
          defaultOpen: true,
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
          href: "",
          label: "Top failed findings",
          icon: Bookmark,
          submenus: [
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=aws%2Cazure%2Cgcp%2Ckubernetes&filter[service__in]=iam%2Crbac&sort=-inserted_at",
              label: "IAM Issues",
              icon: ShieldCheck,
            },
          ],
          defaultOpen: false,
        },
        {
          href: "",
          label: "High-risk findings",
          icon: SquarePen,
          submenus: [
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=aws&sort=severity,-inserted_at",
              label: "Amazon Web Services",
              icon: AWSIcon,
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=azure&sort=severity,-inserted_at",
              label: "Microsoft Azure",
              icon: AzureIcon,
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=m365&sort=severity,-inserted_at",
              label: "Microsoft 365",
              icon: M365Icon,
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=gcp&sort=severity,-inserted_at",
              label: "Google Cloud",
              icon: GCPIcon,
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=kubernetes&sort=severity,-inserted_at",
              label: "Kubernetes",
              icon: KubernetesIcon,
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=github&sort=severity,-inserted_at",
              label: "Github",
              icon: GithubIcon,
            },
          ],
          defaultOpen: false,
        },
        {
          href: "/findings",
          label: "Browse all findings",
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
              // Use trailing slash to prevent both menu items from being active at /providers
              href: "/providers/",
              label: "Mutelist",
              icon: VolumeX,
              disabled: hasProviders === false,
              onClick: openMutelistModal,
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
          href: "https://hub.prowler.com/",
          label: "Prowler Hub",
          icon: ProwlerShort,
          target: "_blank",
          tooltip: "Looking for all available checks? learn more.",
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
              href: "https://github.com/prowler-cloud/prowler/issues",
              target: "_blank",
              label: "Support",
              icon: CircleHelpIcon,
            },
          ],
          defaultOpen: false,
        },
      ],
    },
  ];
};
