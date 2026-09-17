// Closed buckets the onboarding profile step asks at a new tenant's first
// login. Values mirror `TenantOnboardingProfile` choices in the API and the
// `declared_*` PostHog properties; change them together.

export const DECLARED_CLOUD_ACCOUNTS = {
  ONE: "1",
  TWO_TO_TEN: "2-10",
  ELEVEN_TO_FIFTY: "11-50",
  FIFTY_ONE_TO_TWO_HUNDRED: "51-200",
  OVER_TWO_HUNDRED: "200+",
} as const;

export type DeclaredCloudAccounts =
  (typeof DECLARED_CLOUD_ACCOUNTS)[keyof typeof DECLARED_CLOUD_ACCOUNTS];

// Discipline, not rank. Management lives in DECLARED_SENIORITY so the two
// questions stay orthogonal: a security engineer and a CISO both answer
// "security" here and differ on the ladder below.
export const DECLARED_ROLE = {
  SECURITY: "security",
  DEVOPS_PLATFORM: "devops_platform",
  DEVELOPER: "developer",
  COMPLIANCE_GRC: "compliance_grc",
  OTHER: "other",
} as const;

export type DeclaredRole = (typeof DECLARED_ROLE)[keyof typeof DECLARED_ROLE];

// How far up the organisation the answer comes from. Founders get their own
// bucket: a one-person tenant run by a founder evaluating Prowler is a
// different prospect from a lone practitioner inside a large company.
export const DECLARED_SENIORITY = {
  PRACTITIONER: "practitioner",
  LEAD: "lead",
  DIRECTOR: "director",
  EXECUTIVE: "executive",
  FOUNDER: "founder",
} as const;

export type DeclaredSeniority =
  (typeof DECLARED_SENIORITY)[keyof typeof DECLARED_SENIORITY];

export interface OnboardingProfileAnswers {
  declared_cloud_accounts: DeclaredCloudAccounts;
  declared_role: DeclaredRole;
  declared_seniority: DeclaredSeniority;
}

export const DECLARED_ROLE_LABEL: Record<DeclaredRole, string> = {
  [DECLARED_ROLE.SECURITY]: "Security",
  [DECLARED_ROLE.DEVOPS_PLATFORM]: "DevOps / Platform",
  [DECLARED_ROLE.DEVELOPER]: "Developer",
  [DECLARED_ROLE.COMPLIANCE_GRC]: "Compliance / GRC",
  [DECLARED_ROLE.OTHER]: "Other",
};

export const DECLARED_SENIORITY_LABEL: Record<DeclaredSeniority, string> = {
  [DECLARED_SENIORITY.PRACTITIONER]: "Practitioner / IC",
  [DECLARED_SENIORITY.LEAD]: "Team lead / Manager",
  [DECLARED_SENIORITY.DIRECTOR]: "Director / Head of",
  [DECLARED_SENIORITY.EXECUTIVE]: "VP / C-level",
  [DECLARED_SENIORITY.FOUNDER]: "Founder / Owner",
};
