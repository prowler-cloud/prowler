// Generic JSON:API v1.1 shells shared by feature adapters; feature code
// models its attribute payloads and reuses these instead of re-declaring them.
export interface JsonApiResource<TAttributes, TMeta = Record<string, unknown>> {
  id: string;
  type: string;
  attributes: TAttributes;
  meta?: TMeta;
}

export interface JsonApiDocument<TData, TMeta = Record<string, unknown>> {
  data?: TData;
  meta?: TMeta;
  links?: Record<string, string | null>;
  error?: string;
  errors?: unknown[];
  status?: number;
}
