import {
  Bookmark,
  LayoutGrid,
  LucideIcon,
  Settings,
  SquarePen,
  Tag,
  Users,
} from "lucide-react";

type Submenu = {
  href: string;
  label: string;
  active?: boolean;
};

type Menu = {
  href: string;
  label: string;
  active?: boolean;
  icon: LucideIcon;
  submenus?: Submenu[];
  defaultOpen?: boolean;
};

type Group = {
  groupLabel: string;
  menus: Menu[];
};

export function getMenuList(pathname: string): Group[] {
  return [
    {
      groupLabel: "",
      menus: [
        {
          href: "",
          label: "Analytics",
          icon: LayoutGrid,
          submenus: [
            { href: "/", label: "Overview" },
            { href: "/compliance", label: "Compliance" },
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
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=aws%2Cazure%2Cgcp%2Ckubernetes&filter[service__in]=iam%2Crbac&sort=-inserted_at",
              label: "IAM Issues",
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
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=azure&sort=severity,-inserted_at",
              label: "Microsoft Azure",
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=gcp&sort=severity,-inserted_at",
              label: "Google Cloud",
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=kubernetes&sort=severity,-inserted_at",
              label: "Kubernetes",
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
          href: "",
          label: "Settings",
          icon: Settings,
          submenus: [
            { href: "/providers", label: "Cloud Providers" },
            { href: "/manage-groups", label: "Provider Groups" },
            { href: "/scans", label: "Scan Jobs" },
            { href: "/roles", label: "Roles" },
          ],
          defaultOpen: true,
        },
      ],
    },
    {
      groupLabel: "Memberships",
      menus: [
        {
          href: "",
          label: "Memberships",
          icon: Users,
          submenus: [
            { href: "/users", label: "Users" },
            { href: "/invitations", label: "Invitations" },
          ],
          defaultOpen: false,
        },
      ],
    },
  ];
}
