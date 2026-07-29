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

    // Note: Provider and scan data is intentionally NOT included here.
    // The LLM must use MCP tools to fetch real-time provider/findings data
    // to ensure it always works with current information.

    return `
**TODAY'S DATE:**
${new Date().toISOString()}

**CURRENT USER DATA:**
Information about the current user interacting with the chatbot:
User: ${userData.name}
Email: ${userData.email}
Company: ${userData.company}
`;
  } catch (error) {
    console.error("Failed to retrieve current data:", error);
    return "**CURRENT DATA: Not available**";
  }
}
