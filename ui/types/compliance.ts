export const REQUIREMENT_STATUS = {
  PASS: "PASS",
  FAIL: "FAIL",
  MANUAL: "MANUAL",
  NO_FINDINGS: "No findings",
} as const;

export type RequirementStatus =
  (typeof REQUIREMENT_STATUS)[keyof typeof REQUIREMENT_STATUS];

export const COMPLIANCE_OVERVIEW_TYPE = {
  OVERVIEW: "compliance-overviews",
  REQUIREMENTS_STATUS: "compliance-requirements-status",
} as const;

export type ComplianceOverviewType =
  (typeof COMPLIANCE_OVERVIEW_TYPE)[keyof typeof COMPLIANCE_OVERVIEW_TYPE];

export interface CompliancesOverview {
  data: ComplianceOverviewData[];
}

export interface ComplianceOverviewData {
  type: ComplianceOverviewType;
  id: string;
  attributes: {
    framework: string;
    version: string;
    requirements_passed: number;
    requirements_failed: number;
    requirements_manual: number;
    total_requirements: number;
  };
}

export interface Requirement {
  name: string;
  description: string;
  status: RequirementStatus;
  pass: number;
  fail: number;
  manual: number;
  check_ids: string[];
  // This is to allow any key to be added to the requirement object
  // because each compliance has different keys
  [key: string]: string | string[] | number | boolean | object[] | undefined;
}

export interface Control {
  label: string;
  pass: number;
  fail: number;
  manual: number;
  requirements: Requirement[];
}

export interface Category {
  name: string;
  pass: number;
  fail: number;
  manual: number;
  controls: Control[];
}

export interface Framework {
  name: string;
  pass: number;
  fail: number;
  manual: number;
  categories: Category[];
  // Optional: flat structure for frameworks like MITRE that don't have categories
  requirements?: Requirement[];
}

export interface FailedSection {
  name: string;
  total: number;
  types?: Record<string, number>;
}

export const TOP_FAILED_DATA_TYPE = {
  SECTIONS: "sections",
  REQUIREMENTS: "requirements",
} as const;

export type TopFailedDataType =
  (typeof TOP_FAILED_DATA_TYPE)[keyof typeof TOP_FAILED_DATA_TYPE];

export interface TopFailedResult {
  items: FailedSection[];
  type: TopFailedDataType;
}

export interface RequirementsTotals {
  pass: number;
  fail: number;
  manual: number;
}

// API Responses types:
export interface ENSAttributesMetadata {
  IdGrupoControl: string;
  Marco: string;
  Categoria: string;
  DescripcionControl: string;
  Tipo: string;
  Nivel: string;
  Dimensiones: string[];
  ModoEjecucion: string;
  Dependencias: unknown[];
}

export interface ISO27001AttributesMetadata {
  Category: string;
  Objetive_ID: string;
  Objetive_Name: string;
  Check_Summary: string;
}

export interface CISAttributesMetadata {
  Section: string;
  SubSection: string | null;
  Profile: string; // "Level 1" or "Level 2"
  AssessmentStatus: string; // "Manual" or "Automated"
  Description: string;
  RationaleStatement: string;
  ImpactStatement: string;
  RemediationProcedure: string;
  AuditProcedure: string;
  AdditionalInformation: string;
  DefaultValue: string | null;
  References: string;
}

export interface AWSWellArchitectedAttributesMetadata {
  Name: string;
  WellArchitectedQuestionId: string;
  WellArchitectedPracticeId: string;
  Section: string;
  SubSection: string;
  LevelOfRisk: string;
  AssessmentMethod: string;
  Description: string;
  ImplementationGuidanceUrl: string;
}

export interface ThreatAttributesMetadata {
  Title: string;
  Section: string;
  SubSection: string;
  AttributeDescription: string;
  AdditionalInformation: string;
  LevelOfRisk: number;
  Weight: number;
}

export interface KISAAttributesMetadata {
  Domain: string;
  Subdomain: string;
  Section: string;
  AuditChecklist: string[];
  RelatedRegulations: string[];
  AuditEvidence: string[];
  NonComplianceCases: string[];
}

export interface C5AttributesMetadata {
  Section: string;
  SubSection: string;
  Type: string;
  AboutCriteria: string;
  ComplementaryCriteria: string;
}

export interface MITREAttributesMetadata {
  // Dynamic cloud service field - could be AWSService, GCPService, AzureService, etc.
  [key: string]: string;
  Category: string; // "Protect", "Detect", "Respond"
  Value: string; // "Minimal", "Partial", "Significant"
  Comment: string;
}

export interface GenericAttributesMetadata {
  ItemId: string;
  Section: string;
  SubSection: string;
  SubGroup: string | null;
  Service: string | null;
  Type: string | null;
}

export interface CSAAttributesMetadata {
  Section: string;
  CCMLite: string;
  IaaS: string;
  PaaS: string;
  SaaS: string;
  ScopeApplicability: Array<{
    ReferenceId: string;
    Identifiers: string[];
  }>;
}

export interface CCCAttributesMetadata {
  FamilyName: string;
  FamilyDescription: string;
  Section: string;
  SubSection: string;
  SubSectionObjective: string;
  Applicability: string[];
  Recommendation: string;
  SectionThreatMappings: Array<{
    ReferenceId: string;
    Identifiers: string[];
  }>;
  SectionGuidelineMappings: Array<{
    ReferenceId: string;
    Identifiers: string[];
  }>;
}

export interface AttributesItemData {
  type: "compliance-requirements-attributes";
  id: string;
  attributes: {
    framework_description: string;
    name?: string;
    framework: string;
    version: string;
    description: string;
    attributes: {
      metadata:
        | ENSAttributesMetadata[]
        | ISO27001AttributesMetadata[]
        | CISAttributesMetadata[]
        | AWSWellArchitectedAttributesMetadata[]
        | ThreatAttributesMetadata[]
        | KISAAttributesMetadata[]
        | C5AttributesMetadata[]
        | MITREAttributesMetadata[]
        | CCCAttributesMetadata[]
        | CSAAttributesMetadata[]
        | GenericAttributesMetadata[];
      check_ids: string[];
      // MITRE structure
      technique_details?: {
        tactics: string[];
        subtechniques: string[];
        platforms: string[];
        technique_url: string;
      };
    };
  };
}

export interface RequirementItemData {
  type: "compliance-requirements-details";
  id: string;
  attributes: {
    framework: string;
    version: string;
    description: string;
    status: RequirementStatus;
    // For Threat compliance:
    passed_findings?: number;
    total_findings?: number;
  };
}

export interface AttributesData {
  data: AttributesItemData[];
}

export interface RequirementsData {
  data: RequirementItemData[];
}

export interface RegionData {
  name: string;
  failurePercentage: number;
  totalRequirements: number;
  failedRequirements: number;
}

export interface CategoryData {
  name: string;
  failurePercentage: number;
  totalRequirements: number;
  failedRequirements: number;
}
