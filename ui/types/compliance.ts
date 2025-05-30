export type RequirementStatus = "PASS" | "FAIL" | "MANUAL" | "No findings";

export type ComplianceId =
  | "ens_rd2022_aws"
  | "iso27001_2013_aws"
  | "iso27001_2022_aws";

export interface CompliancesOverview {
  data: ComplianceOverviewData[];
}

export interface ComplianceOverviewData {
  type: "compliance-requirements-status";
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
  [key: string]: string | string[] | number | undefined;
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
}

export interface FailedSection {
  name: string;
  total: number;
  types?: { [key: string]: number };
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
  Dependencias: any[];
}

export interface ISO27001AttributesMetadata {
  Category: string;
  Objetive_ID: string;
  Objetive_Name: string;
  Check_Summary: string;
}

export interface AttributesItemData {
  type: "compliance-requirements-attributes";
  id: string;
  attributes: {
    framework: string;
    version: string;
    description: string;
    attributes: {
      metadata: ENSAttributesMetadata[] | ISO27001AttributesMetadata[];
      check_ids: string[];
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
  };
}

export interface AttributesData {
  data: AttributesItemData[];
}

export interface RequirementsData {
  data: RequirementItemData[];
}
