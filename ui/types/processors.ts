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
