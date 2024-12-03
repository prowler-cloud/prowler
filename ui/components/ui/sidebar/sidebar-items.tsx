import { Icon } from "@iconify/react";
import { Chip } from "@nextui-org/react";

import { SidebarItem, SidebarItemType } from "./sidebar";
import { TeamAvatar } from "./team-avatar";

/**
 * Please check the https://nextui.org/docs/guide/routing to have a seamless router integration
 */

export const items: SidebarItem[] = [
  {
    key: "home",
    href: "#",
    icon: "solar:home-2-linear",
    title: "Home",
  },
  {
    key: "projects",
    href: "#",
    icon: "solar:widget-2-outline",
    title: "Projects",
    endContent: (
      <Icon
        className="text-default-400"
        icon="solar:add-circle-line-duotone"
        width={24}
      />
    ),
  },
  {
    key: "invitations",
    href: "#",
    icon: "solar:checklist-minimalistic-outline",
    title: "Invitations",
    endContent: (
      <Icon
        className="text-default-400"
        icon="solar:add-circle-line-duotone"
        width={24}
      />
    ),
  },
  {
    key: "team",
    href: "#",
    icon: "solar:users-group-two-rounded-outline",
    title: "Team",
  },
  {
    key: "tracker",
    href: "#",
    icon: "solar:sort-by-time-linear",
    title: "Tracker",
    endContent: (
      <Chip size="sm" variant="flat">
        New
      </Chip>
    ),
  },
  {
    key: "analytics",
    href: "#",
    icon: "solar:chart-outline",
    title: "Analytics",
  },
  {
    key: "perks",
    href: "#",
    icon: "solar:gift-linear",
    title: "Perks",
    endContent: (
      <Chip size="sm" variant="flat">
        3
      </Chip>
    ),
  },
  {
    key: "expenses",
    href: "#",
    icon: "solar:bill-list-outline",
    title: "Expenses",
  },
  {
    key: "settings",
    href: "#",
    icon: "solar:settings-outline",
    title: "Settings",
  },
];

export const sectionItems: SidebarItem[] = [
  // {
  //   key: "dashboards",
  //   title: "Dashboard",
  //   items: [
  //     {
  //       key: "overview",
  //       href: "/",
  //       icon: "solar:pie-chart-2-outline",
  //       title: "Overview",
  //     },
  //     {
  //       key: "projects",
  //       href: "#",
  //       icon: "solar:widget-2-outline",
  //       title: "Projects",
  //       endContent: (
  //         <Icon
  //           className="text-default-400"
  //           icon="solar:add-circle-line-duotone"
  //           width={24}
  //         />
  //       ),
  //     },
  //   ],
  // },

  {
    key: "analytics",
    title: "Analytics",
    items: [
      {
        key: "overview",
        href: "/",
        icon: "solar:pie-chart-2-outline",
        title: "Overview",
      },
      {
        key: "compliance",
        href: "/compliance",
        icon: "fluent-mdl2:compliance-audit",
        title: "Compliance",
        // endContent: (
        //   <Chip size="sm" variant="flat">
        //     New
        //   </Chip>
        // ),
      },
      // {
      //   key: "services",
      //   href: "/services",
      //   icon: "material-symbols:linked-services-outline",
      //   title: "Services",
      // },
    ],
  },

  {
    key: "issues",
    title: "Issues",
    items: [
      {
        key: "cloud-misconfigurations",
        href: "/findings?filter[status__in]=FAIL&sort=severity",
        icon: "solar:danger-triangle-linear",
        title: "Cloud Misconfigurations",
      },
      {
        key: "iam-issues",
        href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=aws%2Cazure%2Cgcp%2Ckubernetes&filter[service__in]=iam%2Crbac",
        icon: "solar:shield-user-linear",
        title: "IAM Issues",
      },
      {
        key: "aws-findings",
        href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=aws&sort=severity",
        icon: "ri:amazon-line",
        title: "AWS Top Failed Findings",
      },
      {
        key: "azure-findings",
        href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=azure&sort=severity",
        icon: "ri:microsoft-line",
        title: "Azure Top Failed Findings",
      },
      {
        key: "gcp-findings",
        href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=gcp&sort=severity",
        icon: "ri:google-line",
        title: "GCP Top Failed Findings",
      },
      {
        key: "kubernetes-findings",
        href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=kubernetes&sort=severity",
        icon: "ri:steering-2-line",
        title: "Kubernetes Top Failed Findings",
      },
      {
        key: "all-findings",
        href: "/findings",
        icon: "solar:document-text-linear",
        title: "Browse All Findings",
      },
    ],
  },

  {
    key: "settings",
    title: "Settings",
    items: [
      {
        key: "providers",
        href: "/providers",
        icon: "fluent:cloud-sync-24-regular",
        title: "Cloud Providers",
      },
      {
        key: "scans",
        href: "/scans",
        icon: "lucide:scan-search",
        title: "Scan Jobs",
      },
      // {
      //   key: "integrations",
      //   href: "/integrations",
      //   icon: "tabler:puzzle",
      //   title: "Integrations",
      // },
    ],
  },
];

export const sectionItemsWithTeams: SidebarItem[] = [
  ...sectionItems,
  {
    key: "memberships",
    title: "Membership",
    items: [
      {
        key: "users",
        href: "/users",
        title: "Users",
        icon: "ci:users",
      },
      {
        key: "invitations",
        href: "/invitations",
        icon: "solar:checklist-minimalistic-outline",
        title: "Invitations",
      },
    ],
  },
];

export const brandItems: SidebarItem[] = [
  {
    key: "overview",
    title: "Overview",
    items: [
      {
        key: "home",
        href: "/",
        icon: "solar:home-2-linear",
        title: "Home",
      },
      {
        key: "projects",
        href: "#",
        icon: "solar:widget-2-outline",
        title: "Projects",
        endContent: (
          <Icon
            className="text-primary-foreground/60"
            icon="solar:add-circle-line-duotone"
            width={24}
          />
        ),
      },
      {
        key: "tasks",
        href: "#",
        icon: "solar:checklist-minimalistic-outline",
        title: "Tasks",
        endContent: (
          <Icon
            className="text-primary-foreground/60"
            icon="solar:add-circle-line-duotone"
            width={24}
          />
        ),
      },
      {
        key: "team",
        href: "#",
        icon: "solar:users-group-two-rounded-outline",
        title: "Team",
      },
      {
        key: "tracker",
        href: "#",
        icon: "solar:sort-by-time-linear",
        title: "Tracker",
        endContent: (
          <Chip
            className="bg-primary-foreground font-medium text-primary"
            size="sm"
            variant="flat"
          >
            New
          </Chip>
        ),
      },
    ],
  },
  {
    key: "your-teams",
    title: "Your Teams",
    items: [
      {
        key: "nextui",
        href: "#",
        title: "NextUI",
        startContent: (
          <TeamAvatar
            classNames={{
              base: "border-1 border-primary-foreground/20",
              name: "text-primary-foreground/80",
            }}
            name="Next UI"
          />
        ),
      },
      {
        key: "tailwind-variants",
        href: "#",
        title: "Tailwind Variants",
        startContent: (
          <TeamAvatar
            classNames={{
              base: "border-1 border-primary-foreground/20",
              name: "text-primary-foreground/80",
            }}
            name="Tailwind Variants"
          />
        ),
      },
      {
        key: "nextui-pro",
        href: "#",
        title: "NextUI Pro",
        startContent: (
          <TeamAvatar
            classNames={{
              base: "border-1 border-primary-foreground/20",
              name: "text-primary-foreground/80",
            }}
            name="NextUI Pro"
          />
        ),
      },
    ],
  },
];

export const sectionLongList: SidebarItem[] = [
  ...sectionItems,
  {
    key: "payments",
    title: "Payments",
    items: [
      {
        key: "payroll",
        href: "#",
        title: "Payroll",
        icon: "solar:dollar-minimalistic-linear",
      },
      {
        key: "invoices",
        href: "#",
        title: "Invoices",
        icon: "solar:file-text-linear",
      },
      {
        key: "billing",
        href: "#",
        title: "Billing",
        icon: "solar:card-outline",
      },
      {
        key: "payment-methods",
        href: "#",
        title: "Payment Methods",
        icon: "solar:wallet-money-outline",
      },
      {
        key: "payouts",
        href: "#",
        title: "Payouts",
        icon: "solar:card-transfer-outline",
      },
    ],
  },
  {
    key: "your-teams",
    title: "Your Teams",
    items: [
      {
        key: "nextui",
        href: "#",
        title: "NextUI",
        startContent: <TeamAvatar name="Next UI" />,
      },
      {
        key: "tailwind-variants",
        href: "#",
        title: "Tailwind Variants",
        startContent: <TeamAvatar name="Tailwind Variants" />,
      },
      {
        key: "nextui-pro",
        href: "#",
        title: "NextUI Pro",
        startContent: <TeamAvatar name="NextUI Pro" />,
      },
    ],
  },
];

export const sectionNestedItems: SidebarItem[] = [
  {
    key: "home",
    href: "#",
    icon: "solar:home-2-linear",
    title: "Home",
  },
  {
    key: "projects",
    href: "#",
    icon: "solar:widget-2-outline",
    title: "Projects",
    endContent: (
      <Icon
        className="text-default-400"
        icon="solar:add-circle-line-duotone"
        width={24}
      />
    ),
  },
  {
    key: "tasks",
    href: "#",
    icon: "solar:checklist-minimalistic-outline",
    title: "Tasks",
    endContent: (
      <Icon
        className="text-default-400"
        icon="solar:add-circle-line-duotone"
        width={24}
      />
    ),
  },
  {
    key: "team",
    href: "#",
    icon: "solar:users-group-two-rounded-outline",
    title: "Team",
  },
  {
    key: "tracker",
    href: "#",
    icon: "solar:sort-by-time-linear",
    title: "Tracker",
    endContent: (
      <Chip size="sm" variant="flat">
        New
      </Chip>
    ),
  },
  {
    key: "analytics",
    href: "#",
    icon: "solar:chart-outline",
    title: "Analytics",
  },
  {
    key: "perks",
    href: "#",
    icon: "solar:gift-linear",
    title: "Perks",
    endContent: (
      <Chip size="sm" variant="flat">
        3
      </Chip>
    ),
  },
  {
    key: "cap_table",
    title: "Cap Table",
    icon: "solar:pie-chart-2-outline",
    type: SidebarItemType.Nest,
    items: [
      {
        key: "shareholders",
        icon: "solar:users-group-rounded-linear",
        href: "#",
        title: "Shareholders",
      },
      {
        key: "note_holders",
        icon: "solar:notes-outline",
        href: "#",
        title: "Note Holders",
      },
      {
        key: "transactions_log",
        icon: "solar:clipboard-list-linear",
        href: "#",
        title: "Transactions Log",
      },
    ],
  },
  {
    key: "expenses",
    href: "#",
    icon: "solar:bill-list-outline",
    title: "Expenses",
  },
];
