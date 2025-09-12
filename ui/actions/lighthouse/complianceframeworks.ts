export const getLighthouseComplianceFrameworks = async (
  provider_type: string,
) => {
  const url = new URL(
    `https://hub.prowler.com/api/compliance?fields=id&provider=${provider_type}`,
  );
  const response = await fetch(url.toString(), {
    method: "GET",
  });

  const data = await response.json();
  const frameworks = data.map((item: { id: string }) => item.id);
  return frameworks;
};
