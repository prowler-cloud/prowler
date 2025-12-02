"use server";
import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

import {
  AttackSurfaceOverviewResponse,
  FindingsSeverityOverviewResponse,
  ProvidersOverviewResponse,
  RegionsOverviewResponse,
  ServicesOverviewResponse,
} from "./types";

export const getServicesOverview = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<ServicesOverviewResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/overviews/services`);

  // Handle multiple filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]" && value !== undefined) {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching services overview:", error);
    return undefined;
  }
};

export const getProvidersOverview = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}: {
  page?: number;
  query?: string;
  sort?: string;
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<ProvidersOverviewResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/providers-overview");

  const url = new URL(`${apiBaseUrl}/overviews/providers`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]" && value !== undefined) {
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
}: {
  page?: number;
  query?: string;
  sort?: string;
  filters?: Record<string, string | string[] | undefined>;
} = {}) => {
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
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<FindingsSeverityOverviewResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/overviews/findings_severity`);

  // Handle multiple filters, but exclude unsupported filters
  Object.entries(filters).forEach(([key, value]) => {
    if (
      key !== "filter[search]" &&
      key !== "filter[muted]" &&
      value !== undefined
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

export const getThreatScore = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/overviews/threatscore`);

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
    console.error("Error fetching threat score:", error);
    return undefined;
  }
};

export const getRegionsOverview = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<RegionsOverviewResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/overviews/regions`);

  // Handle multiple filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]" && value !== undefined) {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching regions overview:", error);
    return undefined;
  }
};

export const getAttackSurfaceOverview = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<AttackSurfaceOverviewResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/overviews/attack_surface`);

  // Handle multiple filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]" && value !== undefined) {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching attack surface overview:", error);
    return undefined;
  }
};
