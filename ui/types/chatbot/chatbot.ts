export interface AIInfoDetailResponse {
  data: {
    type: string;
    id: string;
    attributes: {
      name: string;
      model: string;
      temperature: number;
      max_tokens: number;
      business_context: string | null;
      is_active: boolean;
      inserted_at: string;
      updated_at: string;
      api_key: string;
    };
    links: {
      self: string;
    };
  };
  meta: {
    version: string;
  };
}
