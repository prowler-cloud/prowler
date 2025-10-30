"use server";
import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

export const getProvidersOverview = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/providers-overview");

  const url = new URL(`${apiBaseUrl}/overviews/providers`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching providers overview:", error);
    return undefined;
  }
};

export const getFindingsByStatus = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/");

  const url = new URL(`${apiBaseUrl}/overviews/findings`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters, but exclude muted filter as overviews endpoint doesn't support it
  Object.entries(filters).forEach(([key, value]) => {
    // The overviews/findings endpoint does not support status or muted filters
    // (allowed filters include date, region, provider fields). Exclude unsupported ones.
    if (
      key !== "filter[search]" &&
      key !== "filter[muted]" &&
      key !== "filter[status]"
    ) {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching findings severity overview:", error);
    return undefined;
  }
};

export const getFindingsBySeverity = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/");

  const url = new URL(`${apiBaseUrl}/overviews/findings_severity`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters, but exclude unsupported filters
  // The overviews/findings_severity endpoint does not support status or muted filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]" && key !== "filter[muted]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching findings severity overview:", error);
    return undefined;
  }
};

export const getFindingsSeverityTrends = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}) => {
  // TODO: Replace with actual API call when endpoint is available
  // const headers = await getAuthHeaders({ contentType: false });
  // const url = new URL(`${apiBaseUrl}/findings/severity/time-series`);
  // Object.entries(filters).forEach(([key, value]) => {
  //   if (value) url.searchParams.append(key, String(value));
  // });
  // const response = await fetch(url.toString(), { headers });
  // return handleApiResponse(response);

  // Extract date range from filters to simulate different data based on selection
  const startDateStr = filters["filter[inserted_at__gte]"] as
    | string
    | undefined;
  const endDateStr = filters["filter[inserted_at__lte]"] as string | undefined;

  // Generate mock data based on the date range
  let mockData;

  if (startDateStr && endDateStr) {
    const startDate = new Date(startDateStr);
    const endDate = new Date(endDateStr);
    const daysDiff = Math.ceil(
      (endDate.getTime() - startDate.getTime()) / (24 * 60 * 60 * 1000),
    );

    // Generate data points for each day in the range
    const dataPoints = [];
    for (let i = 0; i <= daysDiff; i++) {
      const currentDate = new Date(startDate);
      currentDate.setDate(currentDate.getDate() + i);
      const dateStr = currentDate.toISOString().split("T")[0];

      // Vary the data based on the day for visual difference
      const dayOffset = i;
      dataPoints.push({
        type: "severity-time-series",
        id: dateStr,
        date: `${dateStr}T00:00:00Z`,
        informational: Math.max(0, 380 + dayOffset * 15),
        low: Math.max(0, 720 + dayOffset * 20),
        medium: Math.max(0, 550 + dayOffset * 10),
        high: Math.max(0, 1000 - dayOffset * 5),
        critical: Math.max(0, 1200 - dayOffset * 30),
        muted: Math.max(0, 500 - dayOffset * 25),
      });
    }

    mockData = {
      data: dataPoints,
      links: {
        self: `https://api.prowler.com/api/v1/findings/severity/time-series?start=${startDateStr}&end=${endDateStr}`,
      },
      meta: {
        date_range: `${startDateStr} to ${endDateStr}`,
        days: daysDiff,
        granularity: "daily",
        timezone: "UTC",
      },
    };
  } else {
    // Default 5-day data if no date range provided
    mockData = {
      data: [
        {
          type: "severity-time-series",
          id: "2025-10-26",
          date: "2025-10-26T00:00:00Z",
          informational: 420,
          low: 950,
          medium: 720,
          high: 1150,
          critical: 1350,
          muted: 600,
        },
        {
          type: "severity-time-series",
          id: "2025-10-27",
          date: "2025-10-27T00:00:00Z",
          informational: 450,
          low: 1100,
          medium: 850,
          high: 1300,
          critical: 1500,
          muted: 700,
        },
        {
          type: "severity-time-series",
          id: "2025-10-28",
          date: "2025-10-28T00:00:00Z",
          informational: 400,
          low: 850,
          medium: 650,
          high: 1200,
          critical: 2000,
          muted: 750,
        },
        {
          type: "severity-time-series",
          id: "2025-10-29",
          date: "2025-10-29T00:00:00Z",
          informational: 380,
          low: 720,
          medium: 550,
          high: 1000,
          critical: 1200,
          muted: 500,
        },
        {
          type: "severity-time-series",
          id: "2025-10-30",
          date: "2025-10-30T00:00:00Z",
          informational: 500,
          low: 750,
          medium: 350,
          high: 1000,
          critical: 550,
          muted: 100,
        },
      ],
      links: {
        self: "https://api.prowler.com/api/v1/findings/severity/time-series?range=5D",
      },
      meta: {
        time_range: "5D",
        granularity: "daily",
        timezone: "UTC",
      },
    };
  }

  return mockData;
};
