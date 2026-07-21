// Generic JSON:API v1.1 shells shared by feature adapters; feature code
// models its attribute payloads and reuses these instead of re-declaring them.
export interface JsonApiResource<TAttributes> {
  id: string;
  type: string;
  attributes: TAttributes;
  meta?: Record<string, unknown>;
}

export interface JsonApiDocument<TData> {
  data?: TData;
  meta?: Record<string, unknown>;
  links?: Record<string, string | null>;
  error?: string;
  errors?: unknown[];
  status?: number;
}
