export const DEPLOYMENT_MODE = {
  CLOUD: "cloud",
  ON_PREMISE: "onpremise",
} as const;

export const ENTERPRISE_FEATURE_ENV = {
  BILLING_ENABLED: "NEXT_PUBLIC_PROWLER_ENTERPRISE_BILLING_ENABLED",
  GROUPED_JIRA_DISPATCH_ENABLED:
    "NEXT_PUBLIC_PROWLER_ENTERPRISE_GROUPED_JIRA_DISPATCH_ENABLED",
  POSTHOG_ENABLED: "NEXT_PUBLIC_PROWLER_ENTERPRISE_POSTHOG_ENABLED",
} as const;

export const PROWLER_CLOUD_ONLY_TOOLTIP = "Available only in Prowler Cloud";

export type DeploymentMode =
  (typeof DEPLOYMENT_MODE)[keyof typeof DEPLOYMENT_MODE];

type EnterpriseFeatureEnv =
  (typeof ENTERPRISE_FEATURE_ENV)[keyof typeof ENTERPRISE_FEATURE_ENV];

const getEnterpriseFeatureValue = (
  envName: EnterpriseFeatureEnv,
): string | undefined => {
  if (envName === ENTERPRISE_FEATURE_ENV.BILLING_ENABLED) {
    return process.env.NEXT_PUBLIC_PROWLER_ENTERPRISE_BILLING_ENABLED;
  }

  if (envName === ENTERPRISE_FEATURE_ENV.GROUPED_JIRA_DISPATCH_ENABLED) {
    return process.env
      .NEXT_PUBLIC_PROWLER_ENTERPRISE_GROUPED_JIRA_DISPATCH_ENABLED;
  }

  return process.env.NEXT_PUBLIC_PROWLER_ENTERPRISE_POSTHOG_ENABLED;
};

const getBooleanEnv = (
  envName: EnterpriseFeatureEnv,
  defaultValue: boolean,
): boolean => {
  const value = getEnterpriseFeatureValue(envName);

  if (value === undefined || value === "") {
    return defaultValue;
  }

  return value === "true";
};

export const getDeploymentMode = (): DeploymentMode | undefined => {
  const mode = process.env.NEXT_PUBLIC_PROWLER_DEPLOYMENT_MODE;

  if (mode === DEPLOYMENT_MODE.CLOUD || mode === DEPLOYMENT_MODE.ON_PREMISE) {
    return mode;
  }

  return undefined;
};

export const isOnPremiseDeployment = (): boolean =>
  getDeploymentMode() === DEPLOYMENT_MODE.ON_PREMISE;

export const isBillingEnabled = (): boolean =>
  getBooleanEnv(ENTERPRISE_FEATURE_ENV.BILLING_ENABLED, true);

export const isPostHogEnabled = (): boolean =>
  isBillingEnabled() ||
  getBooleanEnv(ENTERPRISE_FEATURE_ENV.POSTHOG_ENABLED, true);

export const isGroupedJiraDispatchEnabled = (): boolean =>
  getDeploymentMode() === DEPLOYMENT_MODE.CLOUD &&
  getBooleanEnv(ENTERPRISE_FEATURE_ENV.GROUPED_JIRA_DISPATCH_ENABLED, false);
