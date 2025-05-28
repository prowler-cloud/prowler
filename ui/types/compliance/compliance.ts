export type RequirementStatus = "PASS" | "FAIL" | "MANUAL" | "No findings";

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
  type: string;
  pass: number;
  fail: number;
  manual: number;
  check_ids: string[];
  nivel: string;
  dimensiones: string[];
}

export interface Control {
  label: string;
  type: string;
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

export type MappedComplianceData = Framework[];

export interface FailedSection {
  name: string;
  total: number;
  types: { [key: string]: number };
}

export interface RequirementsTotals {
  pass: number;
  fail: number;
  manual: number;
}

// API Responses types:
export interface AttributesMetadata {
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

export interface AttributesItemData {
  type: "compliance-requirements-attributes";
  id: string;
  attributes: {
    framework: string;
    version: string;
    description: string;
    attributes: {
      metadata: AttributesMetadata[];
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
