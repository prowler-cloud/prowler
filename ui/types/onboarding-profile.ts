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

export const DECLARED_TEAM_SIZE = {
  ONE: "1",
  TWO_TO_FIVE: "2-5",
  SIX_TO_TWENTY: "6-20",
  OVER_TWENTY: "21+",
} as const;

export type DeclaredTeamSize =
  (typeof DECLARED_TEAM_SIZE)[keyof typeof DECLARED_TEAM_SIZE];

export const DECLARED_ROLE = {
  SECURITY: "security",
  DEVOPS_PLATFORM: "devops_platform",
  DEVELOPER: "developer",
  MANAGEMENT: "management",
  OTHER: "other",
} as const;

export type DeclaredRole = (typeof DECLARED_ROLE)[keyof typeof DECLARED_ROLE];

export interface OnboardingProfileAnswers {
  declared_cloud_accounts: DeclaredCloudAccounts;
  declared_team_size: DeclaredTeamSize;
  declared_role: DeclaredRole;
}

export const DECLARED_ROLE_LABEL: Record<DeclaredRole, string> = {
  [DECLARED_ROLE.SECURITY]: "Security",
  [DECLARED_ROLE.DEVOPS_PLATFORM]: "DevOps / Platform",
  [DECLARED_ROLE.DEVELOPER]: "Developer",
  [DECLARED_ROLE.MANAGEMENT]: "Management",
  [DECLARED_ROLE.OTHER]: "Other",
};
