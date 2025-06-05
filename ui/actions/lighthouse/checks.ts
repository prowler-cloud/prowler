export const getLighthouseProviderChecks = async ({
  providerType,
  service,
  severity,
  compliances,
}: {
  providerType: string;
  service: string[];
  severity: string[];
  compliances: string[];
}) => {
  const url = new URL(
    `https://hub.prowler.com/api/check?fields=id&providers=${providerType}`,
  );
  if (service) {
    url.searchParams.append("services", service.join(","));
  }
  if (severity) {
    url.searchParams.append("severities", severity.join(","));
  }
  if (compliances) {
    url.searchParams.append("compliances", compliances.join(","));
  }

  const response = await fetch(url.toString(), {
    method: "GET",
  });

  const data = await response.json();
  const ids = data.map((item: { id: string }) => item.id);
  return ids;
};

export const getLighthouseCheckDetails = async ({
  checkId,
}: {
  checkId: string;
}) => {
  const url = new URL(`https://hub.prowler.com/api/check/${checkId}`);
  const response = await fetch(url.toString(), {
    method: "GET",
  });
  const data = await response.json();
  return data;
};
