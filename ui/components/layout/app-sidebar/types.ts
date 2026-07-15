import type { IconComponent } from "@/types";
import type { CloudUpgradeFeature } from "@/types/cloud-upgrade";

export const APP_SIDEBAR_MODE = {
  BROWSE: "browse",
  CHAT: "chat",
} as const;

export type AppSidebarMode =
  (typeof APP_SIDEBAR_MODE)[keyof typeof APP_SIDEBAR_MODE];

export const NAVIGATION_ITEM_KIND = {
  LINK: "link",
  COLLAPSIBLE: "collapsible",
  CLOUD_UPGRADE: "cloud_upgrade",
} as const;

interface NavigationLabel {
  label: string;
}

export interface NavigationLink extends NavigationLabel {
  kind: typeof NAVIGATION_ITEM_KIND.LINK;
  href: string;
  icon: IconComponent;
  active?: boolean;
  highlight?: boolean;
  target?: string;
  tooltip?: string;
}

export interface NavigationChildLink extends NavigationLabel {
  kind: typeof NAVIGATION_ITEM_KIND.LINK;
  href: string;
  active?: boolean;
  disabled?: boolean;
  highlight?: boolean;
  target?: string;
}

export interface NavigationCloudUpgrade extends NavigationLabel {
  kind: typeof NAVIGATION_ITEM_KIND.CLOUD_UPGRADE;
  cloudUpgradeFeature: CloudUpgradeFeature;
}

export type NavigationChild = NavigationChildLink | NavigationCloudUpgrade;

export interface NavigationCollapsible extends NavigationLabel {
  kind: typeof NAVIGATION_ITEM_KIND.COLLAPSIBLE;
  icon: IconComponent;
  children: NavigationChild[];
  defaultOpen: boolean;
}

export type NavigationItem = NavigationLink | NavigationCollapsible;

export interface NavigationSection {
  label?: string;
  items: NavigationItem[];
}

export type AppSidebarSelectionHandler = () => HTMLElement | null;
