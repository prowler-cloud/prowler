import {
  AlertCircle,
  Bookmark,
  Boxes,
  Cloud,
  CloudCog,
  Database,
  Group,
  LayoutGrid,
  LucideIcon,
  Mail,
  Server,
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

type Submenu = {
  href: string;
  label: string;
  active?: boolean;
  icon: LucideIcon;
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

export const getMenuList = (): Group[] => {
  return [
    {
      groupLabel: "",
      menus: [
        {
          href: "",
          label: "Analytics",
          icon: LayoutGrid,
          submenus: [
            { href: "/", label: "Overview", icon: SquareChartGantt },
            { href: "/compliance", label: "Compliance", icon: ShieldCheck },
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
              icon: Cloud,
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=azure&sort=severity,-inserted_at",
              label: "Microsoft Azure",
              icon: Database,
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=gcp&sort=severity,-inserted_at",
              label: "Google Cloud",
              icon: Server,
            },
            {
              href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=kubernetes&sort=severity,-inserted_at",
              label: "Kubernetes",
              icon: Boxes,
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
  ];
};
