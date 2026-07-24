import { isCloud } from "./shared/env";

export const DEPLOYMENT_MODE = {
  CLOUD: "cloud",
  ON_PREMISE: "onpremise",
} as const;

export const PROWLER_CLOUD_ONLY_TOOLTIP = "Available only in Prowler Cloud";

export type DeploymentMode =
  (typeof DEPLOYMENT_MODE)[keyof typeof DEPLOYMENT_MODE];

export const getDeploymentMode = (): DeploymentMode | undefined => {
  const mode = process.env.NEXT_PUBLIC_PROWLER_DEPLOYMENT_MODE;

  if (mode === DEPLOYMENT_MODE.CLOUD || mode === DEPLOYMENT_MODE.ON_PREMISE) {
    return mode;
  }

  return undefined;
};

export const isGroupedJiraDispatchEnabled = (): boolean => isCloud();
