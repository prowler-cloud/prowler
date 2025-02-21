import { SidebarItem, SidebarItemType } from "./sidebar";

/**
 * Please check the https://nextui.org/docs/guide/routing to have a seamless router integration
 */

export const sectionItems: SidebarItem[] = [
  {
    key: "analytics",
    title: "Analytics",
    icon: "solar:chart-outline",
    type: SidebarItemType.Nest,
    defaultExpanded: true,
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
    ],
  },
  {
    key: "high_risk_findings",
    title: "High-risk findings",
    icon: "solar:bug-linear",
    type: SidebarItemType.Nest,
    items: [
      {
        key: "aws-findings",
        href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=aws&sort=severity,-inserted_at",
        icon: "ri:amazon-line",
        title: "AWS",
      },
      {
        key: "azure-findings",
        icon: "ri:microsoft-line",
        href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=azure&sort=severity,-inserted_at",
        title: "Azure",
      },
      {
        key: "gcp-findings",
        icon: "ri:google-line",
        href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=gcp&sort=severity,-inserted_at",
        title: "Google Cloud",
      },
      {
        key: "kubernetes-findings",
        icon: "ri:steering-2-line",
        href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=kubernetes&sort=severity,-inserted_at",
        title: "Kubernetes",
      },
    ],
  },

  {
    key: "top_failed_issues",
    title: "Top failed issues",
    icon: "solar:danger-circle-linear",
    type: SidebarItemType.Nest,
    items: [
      {
        key: "misconfigurations",
        href: "/findings?filter[status__in]=FAIL&sort=severity,-inserted_at",
        icon: "solar:danger-triangle-linear",
        title: "Misconfigurations",
      },
      {
        key: "iam-issues",
        href: "/findings?filter[status__in]=FAIL&filter[severity__in]=critical%2Chigh%2Cmedium&filter[provider_type__in]=aws%2Cazure%2Cgcp%2Ckubernetes&filter[service__in]=iam%2Crbac&sort=-inserted_at",
        icon: "solar:shield-user-linear",
        title: "IAM Issues",
      },
    ],
  },

  {
    key: "all_findings",
    href: "/findings",
    icon: "solar:document-text-linear",
    title: "Browse all findings",
  },

  {
    key: "settings",
    title: "Settings",
    icon: "solar:settings-outline",
    type: SidebarItemType.Nest,
    defaultExpanded: true,
    items: [
      {
        key: "providers",
        href: "/providers",
        icon: "fluent:cloud-sync-24-regular",
        title: "Cloud Providers",
      },
      {
        key: "provider-groups",
        href: "/manage-groups",
        icon: "solar:settings-outline",
        title: "Provider Groups",
      },
      {
        key: "scans",
        href: "/scans",
        icon: "lucide:scan-search",
        title: "Scan Jobs",
      },
      {
        key: "roles",
        href: "/roles",
        icon: "mdi:account-key-outline",
        title: "Roles",
      },
      // {
      //   key: "integrations",
      //   href: "/integrations",
      //   icon: "tabler:puzzle",
      //   title: "Integrations",
      // },
    ],
  },
  {
    key: "memberships",
    title: "Memberships",
    icon: "solar:users-group-two-rounded-outline",
    type: SidebarItemType.Nest,
    defaultExpanded: false,
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
