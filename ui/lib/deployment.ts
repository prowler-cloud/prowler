export const DEPLOYMENT_MODE = {
  CLOUD: "cloud",
  ON_PREMISE: "onpremise",
} as const;

export const ENTERPRISE_FEATURE_ENV = {
  GROUPED_JIRA_DISPATCH_ENABLED:
    "NEXT_PUBLIC_PROWLER_ENTERPRISE_GROUPED_JIRA_DISPATCH_ENABLED",
} as const;

export const PROWLER_CLOUD_ONLY_TOOLTIP = "Available only in Prowler Cloud";

export type DeploymentMode =
  (typeof DEPLOYMENT_MODE)[keyof typeof DEPLOYMENT_MODE];

type EnterpriseFeatureEnv =
  (typeof ENTERPRISE_FEATURE_ENV)[keyof typeof ENTERPRISE_FEATURE_ENV];

const getEnterpriseFeatureValue = (
  envName: EnterpriseFeatureEnv,
): string | undefined => {
  if (envName === ENTERPRISE_FEATURE_ENV.GROUPED_JIRA_DISPATCH_ENABLED) {
    return process.env
      .NEXT_PUBLIC_PROWLER_ENTERPRISE_GROUPED_JIRA_DISPATCH_ENABLED;
  }

  return undefined;
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

export const isGroupedJiraDispatchEnabled = (): boolean =>
  getDeploymentMode() === DEPLOYMENT_MODE.CLOUD &&
  getBooleanEnv(ENTERPRISE_FEATURE_ENV.GROUPED_JIRA_DISPATCH_ENABLED, false);
