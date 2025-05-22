"use server";

import { getProviders } from "@/actions/providers/providers";
import { getScans } from "@/actions/scans/scans";
import { getUserInfo } from "@/actions/users/users";

// Cache storage
type CacheStore = {
  [userId: string]: {
    data: CachedData;
    timestamp: number;
  };
};

// In-memory cache store
const cacheStore: CacheStore = {};

// Cache metadata
let cacheVersion = Date.now();
let cacheCreatedAt = new Date().toISOString();
let cacheHits = 0;
let cacheMisses = 0;

// Type definition for our cached data
interface CachedData {
  user: {
    name: string;
    email: string;
    company: string;
  };
  providers: Array<{
    name: string;
    provider_type: string;
    alias: string;
    id: string;
    last_checked_at: string;
    scan_id?: string;
    scan_duration?: string;
    resource_count?: number;
  }>;
}

// Function to fetch all required data from APIs
const fetchDataFromAPIs = async (): Promise<CachedData> => {
  cacheMisses++;

  // Step 1: Get user profile data
  const profileData = await getUserInfo();

  if (!profileData || !profileData.data) {
    throw new Error("Unable to fetch user profile data");
  }

  const userData = {
    name: profileData.data.attributes?.name || "",
    email: profileData.data.attributes?.email || "",
    company: profileData.data.attributes?.company_name || "",
  };

  // Step 2: Get providers data
  const providersData = await getProviders({});

  if (!providersData || !providersData.data) {
    throw new Error("Unable to fetch providers data");
  }

  // Step 3: Extract required provider fields
  const providerEntries = providersData.data.map((provider: any) => ({
    alias: provider.attributes?.alias || "Unknown",
    name: provider.attributes?.uid || "Unknown",
    provider_type: provider.attributes?.provider || "Unknown",
    id: provider.id || "Unknown",
    last_checked_at:
      provider.attributes?.connection?.last_checked_at || "Unknown",
  }));

  // Step 4: For each provider, fetch scan data
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

  return {
    user: userData,
    providers: providersWithScans,
  };
};

// Get the current user ID from profile info
export const getCurrentUserId = async (): Promise<string> => {
  const profileInfo = await getUserInfo();
  if (!profileInfo || !profileInfo.data || !profileInfo.data.id) {
    throw new Error("Unable to get current user ID");
  }
  return profileInfo.data.id;
};

// Create or update cache for a user - this will hit APIs
export const createCache = async (userId: string): Promise<CachedData> => {
  const data = await fetchDataFromAPIs();

  // Store in cache
  cacheStore[userId] = {
    data,
    timestamp: Date.now(),
  };

  return data;
};

// Get data from cache if available, fallback to APIs if not
export const getUserCache = async (): Promise<CachedData> => {
  const userId = await getCurrentUserId();

  // Check if we have cached data for this user
  if (userId in cacheStore) {
    cacheHits++;
    return cacheStore[userId].data;
  }

  // If not in cache, fetch and store it
  return await createCache(userId);
};

// Legacy function to maintain compatibility
export const getUserProviders = async () => {
  const data = await getUserCache();
  // Return providers in a format similar to the original getProviders response
  return {
    data: data.providers.map((provider) => ({
      id: provider.id,
      type: "providers",
      attributes: {
        name: provider.name,
        provider_type: provider.provider_type,
        alias: provider.alias,
        connection: {
          last_checked_at: provider.last_checked_at,
        },
      },
    })),
    meta: {
      total_count: data.providers.length,
    },
  };
};

// Function to invalidate cache by removing the user's data from the cache store
export const invalidateCache = async () => {
  const userId = await getCurrentUserId();

  // Delete user's data from cache store
  if (userId in cacheStore) {
    delete cacheStore[userId];
    cacheVersion = Date.now();
    cacheCreatedAt = new Date().toISOString();
  }

  return {
    success: true,
    message: "Cache invalidated successfully",
    newCacheVersion: cacheVersion,
  };
};

// Get cache metadata for display purposes
export const getCacheMetadata = async () => {
  const userId = await getCurrentUserId();

  const userCacheInfo =
    userId in cacheStore
      ? {
          cached: true,
          cachedAt: new Date(cacheStore[userId].timestamp).toISOString(),
        }
      : {
          cached: false,
        };

  return {
    userId,
    cacheVersion,
    cacheCreatedAt,
    cacheHits,
    cacheMisses,
    userCache: userCacheInfo,
    timestamp: new Date().toISOString(),
  };
};

export async function getCachedDataSection(): Promise<string> {
  try {
    const cacheData = await getUserCache();
    if (cacheData) {
      return `
**TODAY'S DATE:**
${new Date().toISOString()}

**CURRENT USER DATA:**
Information about the current user interacting with the chatbot:
User: ${cacheData.user.name}
Email: ${cacheData.user.email}
Company: ${cacheData.user.company}

**CURRENT PROVIDER DATA:**
${cacheData.providers
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
    }
    return "";
  } catch (error) {
    console.error("Failed to retrieve cached data:", error);
    return "**CURRENT DATA: Not available**";
  }
}
