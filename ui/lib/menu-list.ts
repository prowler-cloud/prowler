"use client";

import {
  AlertCircle,
  Bookmark,
  Bot,
  CloudCog,
  Cog,
  Group,
  LayoutGrid,
  Mail,
  Settings,
  ShieldCheck,
  SquareChartGantt,
  SquarePen,
  Tag,
  Timer,
  User,
  UserCog,
  Users,
} from "lucide-react";

import {
  APIdocIcon,
  AWSIcon,
  AzureIcon,
  CircleHelpIcon,
  DocIcon,
  GCPIcon,
  KubernetesIcon,
  M365Icon,
  SupportIcon,
} from "@/components/icons/Icons";
import { GroupProps } from "@/types";

export const getMenuList = (pathname: string): GroupProps[] => {
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
      groupLabel: "Issues",
      menus: [
        {
          href: "",
          label: "Top failed issues",
          icon: Bookmark,
          submenus: [
            {
              href: "/findings?filter[status__in]=FAIL&sort=severity,-inserted_at",
              label: "Misconfigurations",
              icon: AlertCircle,
            },
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
      groupLabel: "Settings",
      menus: [
        {
          href: "",
          label: "Configuration",
          icon: Settings,
          submenus: [
            { href: "/providers", label: "Cloud Providers", icon: CloudCog },
            { href: "/manage-groups", label: "Provider Groups", icon: Group },
            { href: "/scans", label: "Scan Jobs", icon: Timer },
            { href: "/roles", label: "Roles", icon: UserCog },
            { href: "/lighthouse/config", label: "Lighthouse", icon: Cog },
          ],
          defaultOpen: true,
        },
      ],
    },
    {
      groupLabel: "Workspace",
      menus: [
        {
          href: "",
          label: "Memberships",
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
      groupLabel: "Prowler Lighthouse",
      menus: [
        {
          href: "/lighthouse",
          label: "Lighthouse",
          icon: Bot,
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
