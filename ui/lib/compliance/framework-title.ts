export const formatComplianceFrameworkTitle = (
  title: string,
  version?: string,
): string => `${title.split("-").join(" ")}${version ? ` - ${version}` : ""}`;
