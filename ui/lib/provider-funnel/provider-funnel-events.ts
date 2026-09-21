// Window events the add-provider journey dispatches as the user moves through
// it. They carry no listener of their own: a deployment that wants to observe
// the funnel (product analytics, for instance) subscribes from outside, so the
// UI stays free of any tracking dependency. Details are low-cardinality only:
// never a provider uid, alias, ARN or anything typed into a credentials form.
export const PROVIDER_FUNNEL_EVENT = "prowler:provider-funnel";

export const PROVIDER_FUNNEL_STEP = {
  SIDEBAR_CTA_CLICKED: "sidebar_cta_clicked",
  WIZARD_OPENED: "wizard_opened",
  PROVIDER_TYPE_SELECTED: "provider_type_selected",
  METHOD_SELECTED: "method_selected",
  ROLE_TEMPLATE_OPENED: "role_template_opened",
  WIZARD_CLOSED: "wizard_closed",
} as const;

export type ProviderFunnelStep =
  (typeof PROVIDER_FUNNEL_STEP)[keyof typeof PROVIDER_FUNNEL_STEP];

export const SIDEBAR_CTA_VARIANT = {
  ADD_PROVIDER: "add_provider",
  LAUNCH_SCAN: "launch_scan",
} as const;

export type SidebarCtaVariant =
  (typeof SIDEBAR_CTA_VARIANT)[keyof typeof SIDEBAR_CTA_VARIANT];

export const WIZARD_OPEN_SOURCE = {
  FIRST_RUN: "first_run",
  SIDEBAR_CTA: "sidebar_cta",
  URL: "url",
  PAGE_BUTTON: "page_button",
  EMPTY_STATE: "empty_state",
  ROW_ACTION: "row_action",
} as const;

export type WizardOpenSource =
  (typeof WIZARD_OPEN_SOURCE)[keyof typeof WIZARD_OPEN_SOURCE];

export const PROVIDER_FUNNEL_METHOD = {
  SINGLE: "single",
  ORGANIZATION: "organization",
} as const;

export type ProviderFunnelMethod =
  (typeof PROVIDER_FUNNEL_METHOD)[keyof typeof PROVIDER_FUNNEL_METHOD];

export const ROLE_TEMPLATE_KIND = {
  CLOUDFORMATION_QUICK_CREATE: "cloudformation_quick_create",
  CLOUDFORMATION_TEMPLATE: "cloudformation_template",
  TERRAFORM: "terraform",
} as const;

export type RoleTemplateKind =
  (typeof ROLE_TEMPLATE_KIND)[keyof typeof ROLE_TEMPLATE_KIND];

export interface SidebarCtaClickedDetail {
  step: typeof PROVIDER_FUNNEL_STEP.SIDEBAR_CTA_CLICKED;
  variant: SidebarCtaVariant;
}

export interface WizardOpenedDetail {
  step: typeof PROVIDER_FUNNEL_STEP.WIZARD_OPENED;
  source: WizardOpenSource;
}

export interface ProviderTypeSelectedDetail {
  step: typeof PROVIDER_FUNNEL_STEP.PROVIDER_TYPE_SELECTED;
  providerType: string;
}

export interface MethodSelectedDetail {
  step: typeof PROVIDER_FUNNEL_STEP.METHOD_SELECTED;
  providerType: string;
  method: ProviderFunnelMethod;
}

export interface RoleTemplateOpenedDetail {
  step: typeof PROVIDER_FUNNEL_STEP.ROLE_TEMPLATE_OPENED;
  template: RoleTemplateKind;
}

export interface WizardClosedDetail {
  step: typeof PROVIDER_FUNNEL_STEP.WIZARD_CLOSED;
  lastStep: string;
  // A provider record exists; it may still lack credentials or a connection.
  providerCreated: boolean;
}

export type ProviderFunnelDetail =
  | SidebarCtaClickedDetail
  | WizardOpenedDetail
  | ProviderTypeSelectedDetail
  | MethodSelectedDetail
  | RoleTemplateOpenedDetail
  | WizardClosedDetail;

export function dispatchProviderFunnel(detail: ProviderFunnelDetail): void {
  if (typeof window === "undefined") return;
  try {
    window.dispatchEvent(
      new CustomEvent<ProviderFunnelDetail>(PROVIDER_FUNNEL_EVENT, { detail }),
    );
  } catch {
    // A listener that throws must never break the journey it observes.
  }
}
