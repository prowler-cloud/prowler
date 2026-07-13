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
