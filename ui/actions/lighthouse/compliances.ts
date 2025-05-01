import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib/helper";

export const getLighthouseCompliancesOverview = async ({
  scanId, // required
  fields,
  filters,
  page,
  pageSize,
  sort,
}: {
  scanId: string;
  fields?: string[];
  filters?: Record<string, string | number | boolean | undefined>;
  page?: number;
  pageSize?: number;
  sort?: string;
}) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/compliance-overviews`);

  // Required filter
  url.searchParams.append("filter[scan_id]", scanId);

  // Handle optional fields
  if (fields && fields.length > 0) {
    url.searchParams.append("fields[compliance-overviews]", fields.join(","));
  }

  // Handle filters
  if (filters) {
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== "" && value !== null) {
        url.searchParams.append(key, String(value));
      }
    });
  }

  // Handle pagination
  if (page) {
    url.searchParams.append("page[number]", page.toString());
  }
  if (pageSize) {
    url.searchParams.append("page[size]", pageSize.toString());
  }

  // Handle sorting
  if (sort) {
    url.searchParams.append("sort", sort);
  }

  try {
    const compliances = await fetch(url.toString(), {
      headers,
    });
    const data = await compliances.json();
    const parsedData = parseStringify(data);

    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching providers:", error);
    return undefined;
  }
};

export const getLighthouseComplianceOverview = async ({
  complianceId,
  fields,
}: {
  complianceId: string;
  fields?: string[];
}) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/compliance-overviews/${complianceId}`);

  if (fields) {
    url.searchParams.append("fields[compliance-overviews]", fields.join(","));
  }
  const response = await fetch(url.toString(), {
    headers,
  });

  const data = await response.json();
  const parsedData = parseStringify(data);

  return parsedData;
};
