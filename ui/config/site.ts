import { isCloud } from "@/lib/shared/env";

export type SiteConfig = typeof siteConfig;

export const siteConfig = {
  name: isCloud() ? "Prowler Cloud" : "Prowler Local Server",
  description:
    'Prowler is the world\'s most widely used Open-Source Cloud Security Platform that automates security and compliance across any cloud environment. With hundreds of ready-to-use security checks, remediation guidance, and compliance frameworks, Prowler is built to "Secure ANY Cloud at AI Speed". Prowler delivers AI-driven, customizable, and easy-to-use assessments, dashboards, reports, and integrations, making cloud security simple, scalable, and cost-effective for organizations of any size.',
};
