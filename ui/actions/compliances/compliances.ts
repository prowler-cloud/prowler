"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

export const getCompliancesOverview = async ({
  scanId,
  region,
  query,
}: {
  scanId: string;
  region?: string | string[];
  query?: string;
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/compliance-overviews`);

  if (scanId) url.searchParams.append("filter[scan_id]", scanId);
  if (query) url.searchParams.append("filter[search]", query);

  if (region) {
    const regionValue = Array.isArray(region) ? region.join(",") : region;
    url.searchParams.append("filter[region__in]", regionValue);
  }

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching providers:", error);
    return undefined;
  }
};

export const getComplianceOverviewMetadataInfo = async ({
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/compliance-overviews/metadata`);

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    // Define filters to exclude and check for valid values
    if (key !== "filter[search]" && value && String(value).trim() !== "") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliance overview metadata info:", error);
    return undefined;
  }
};

export const getComplianceAttributes = async (complianceId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const url = new URL(`${apiBaseUrl}/compliance-overviews/attributes`);
    url.searchParams.append("filter[compliance_id]", complianceId);

    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliance attributes:", error);
    return undefined;
  }
};

export const getThreatScore = async (scanId: string, provider: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const complianceId = `prowler_threatscore_${provider.toLowerCase()}`;

    // Get attributes
    const attributesUrl = new URL(`${apiBaseUrl}/compliance-overviews/attributes`);
    attributesUrl.searchParams.append("filter[compliance_id]", complianceId);
    const attributesResponse = await fetch(attributesUrl.toString(), { headers });
    const attributesData = await handleApiResponse(attributesResponse);

    // Get requirements
    const requirementsUrl = new URL(`${apiBaseUrl}/compliance-overviews/requirements`);
    requirementsUrl.searchParams.append("filter[compliance_id]", complianceId);
    requirementsUrl.searchParams.append("filter[scan_id]", scanId);
    const requirementsResponse = await fetch(requirementsUrl.toString(), { headers });
    const requirementsData = await handleApiResponse(requirementsResponse);

    if (!attributesData?.data || !requirementsData?.data) {
      return null;
    }

    // Create requirements map
    const requirementsMap = new Map();
    for (const req of requirementsData.data) {
      requirementsMap.set(req.id, req);
    }

    // Calculate ThreatScore using the same formula as threat.tsx
    let numerator = 0;
    let denominator = 0;
    let hasFindings = false;

    for (const attributeItem of attributesData.data) {
      const id = attributeItem.id;
      const metadataArray = attributeItem.attributes?.attributes?.metadata as any[];
      const attrs = metadataArray?.[0];
      if (!attrs) continue;

      const requirementData = requirementsMap.get(id);
      if (!requirementData) continue;

      const pass_i = requirementData.attributes.passed_findings || 0;
      const total_i = requirementData.attributes.total_findings || 0;

      if (total_i === 0) continue;

      hasFindings = true;
      const rate_i = pass_i / total_i;
      const weight_i = attrs.Weight || 1;
      const levelOfRisk = attrs.LevelOfRisk || 0;
      const rfac_i = 1 + 0.25 * levelOfRisk;

      numerator += rate_i * total_i * weight_i * rfac_i;
      denominator += total_i * weight_i * rfac_i;
    }

    const score = !hasFindings ? 100 : denominator > 0 ? (numerator / denominator) * 100 : 0;

    return {
      score: Math.round(score * 100) / 100,
    };
  } catch (error) {
    console.error("Error fetching ThreatScore:", error);
    return null;
  }
};

export const getComplianceRequirements = async ({
  complianceId,
  scanId,
  region,
}: {
  complianceId: string;
  scanId: string;
  region?: string | string[];
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const url = new URL(`${apiBaseUrl}/compliance-overviews/requirements`);
    url.searchParams.append("filter[compliance_id]", complianceId);
    url.searchParams.append("filter[scan_id]", scanId);

    if (region) {
      const regionValue = Array.isArray(region) ? region.join(",") : region;
      url.searchParams.append("filter[region__in]", regionValue);
      //remove page param
    }
    url.searchParams.delete("page");

    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliance requirements:", error);
    return undefined;
  }
};
