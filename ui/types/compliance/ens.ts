export interface Check {
  checkName: string;
  status: string;
}

export interface Requirement {
  name: string;
  description: string;
  status: string;
  type: string;
  pass: number;
  fail: number;
  manual: number;
  checks: Check[];
}

export interface Control {
  label: string;
  type: string;
  pass: number;
  fail: number;
  manual: number;
  requirements: Map<string, Requirement>;
}

export interface Category {
  name: string;
  pass: number;
  fail: number;
  manual: number;
  controls: Map<string, Control>;
}

export interface Framework {
  name: string;
  pass: number;
  fail: number;
  manual: number;
  categories: Map<string, Category>;
}
