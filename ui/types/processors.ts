export interface ProcessorAttributes {
  inserted_at: string;
  updated_at: string;
  processor_type: "mutelist";
  configuration: string;
}

export interface ProcessorData {
  type: "processors";
  id: string;
  attributes: ProcessorAttributes;
}

export interface ProcessorResponse {
  data: ProcessorData;
}

export interface ProcessorsListResponse {
  data: ProcessorData[];
}

export interface ProcessorPayload {
  data: {
    type: "processors";
    attributes: {
      processor_type: "mutelist";
      configuration: string;
    };
  };
}

export interface ProcessorUpdatePayload {
  data: {
    type: "processors";
    id: string;
    attributes: {
      configuration: string;
    };
  };
}

export type MutedFindingsConfigActionState = {
  errors?: {
    configuration?: string;
    general?: string;
  };
  success?: string;
} | null;

export type DeleteMutedFindingsConfigActionState = {
  errors?: {
    general?: string;
  };
  success?: string;
} | null;
