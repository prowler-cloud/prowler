export interface CheckDetails {
  id: string;
  title: string;
  description: string;
  risk: string;
  remediation: {
    cli?: {
      description: string;
      reference: string;
    };
    terraform?: {
      description: string;
      reference: string;
    };
    nativeiac?: {
      description: string;
      reference: string;
    };
    other?: {
      description: string;
      reference: string;
    };
    wui?: {
      description: string;
      reference: string;
    };
  };
}

export interface FindingSummary {
  checkId: string;
  severity: string;
  count: number;
  findingIds: string[];
}
