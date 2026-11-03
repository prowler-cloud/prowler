/**
 * Wraps report downloads. Cloudy has no subscription tier, so every tenant
 * downloads directly. The parameter is kept for call-site compatibility.
 */
export const useReportDownload = (_subscriptionOnly = false) => {
  return (download: () => void | Promise<void>) => download();
};
