export interface ServerActionSuccess<TData> {
  data: TData;
  meta?: Record<string, unknown>;
  links?: Record<string, string | null>;
  status?: number;
}

export interface ServerActionFailure {
  error: string;
  errors?: unknown[];
  status?: number;
}

// Discriminate with `"error" in result` / `"data" in result`.
export type ServerActionResult<TData> =
  | ServerActionSuccess<TData>
  | ServerActionFailure;

export interface ApiErrorResult extends ServerActionFailure {
  status: number;
  data?: never;
}

export interface ApiNoContentResult {
  success: true;
  status: number;
  data?: never;
}

// handleApiResponse resolves the raw JSON:API payload on success, but also
// resolves truthy no-data shapes: {error, status} for 4xx and
// {success, status} for 204/empty bodies. `data?: never` on those members
// keeps `result?.data?.attributes` guards compiling and narrowing correctly.
export type ApiResult<TResponse> =
  | TResponse
  | ApiErrorResult
  | ApiNoContentResult;
