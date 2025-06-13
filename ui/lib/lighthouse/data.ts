import { getProviders } from "@/actions/providers/providers";
import { getScans } from "@/actions/scans/scans";
import { getUserInfo } from "@/actions/users/users";

export async function getCurrentDataSection(): Promise<string> {
  try {
    const profileData = await getUserInfo();

    if (!profileData || !profileData.data) {
      throw new Error("Unable to fetch user profile data");
    }

    const userData = {
      name: profileData.data.attributes?.name || "",
      email: profileData.data.attributes?.email || "",
      company: profileData.data.attributes?.company_name || "",
    };

    const providersData = await getProviders({});

    if (!providersData || !providersData.data) {
      throw new Error("Unable to fetch providers data");
    }

    const providerEntries = providersData.data.map((provider: any) => ({
      alias: provider.attributes?.alias || "Unknown",
      name: provider.attributes?.uid || "Unknown",
      provider_type: provider.attributes?.provider || "Unknown",
      id: provider.id || "Unknown",
      last_checked_at:
        provider.attributes?.connection?.last_checked_at || "Unknown",
    }));

    const providersWithScans = await Promise.all(
      providerEntries.map(async (provider: any) => {
        try {
          // Get scan data for this provider
          const scansData = await getScans({
            page: 1,
            sort: "-inserted_at",
            filters: {
              "filter[provider]": provider.id,
              "filter[state]": "completed",
            },
          });

          // If scans exist, add the scan information to the provider
          if (scansData && scansData.data && scansData.data.length > 0) {
            const latestScan = scansData.data[0];
            return {
              ...provider,
              scan_id: latestScan.id,
              scan_duration: latestScan.attributes?.duration,
              resource_count: latestScan.attributes?.unique_resource_count,
            };
          }

          return provider;
        } catch (error) {
          console.error(
            `Error fetching scans for provider ${provider.id}:`,
            error,
          );
          return provider;
        }
      }),
    );

    return `
**TODAY'S DATE:**
${new Date().toISOString()}

**CURRENT USER DATA:**
Information about the current user interacting with the chatbot:
User: ${userData.name}
Email: ${userData.email}
Company: ${userData.company}

**CURRENT PROVIDER DATA:**
${providersWithScans
  .map(
    (provider, index) => `
Provider ${index + 1}:
- Name: ${provider.name}
- Type: ${provider.provider_type}
- Alias: ${provider.alias}
- Provider ID: ${provider.id}
- Last Checked: ${provider.last_checked_at}
${
  provider.scan_id
    ? `- Latest Scan ID: ${provider.scan_id}
- Scan Duration: ${provider.scan_duration || "Unknown"}
- Resource Count: ${provider.resource_count || "Unknown"}`
    : "- No completed scans found"
}
`,
  )
  .join("\n")}
`;
  } catch (error) {
    console.error("Failed to retrieve current data:", error);
    return "**CURRENT DATA: Not available**";
  }
}
