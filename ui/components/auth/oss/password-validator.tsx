"use client";

import { AlertCircle, CheckCircle } from "lucide-react";

import {
  PASSWORD_REQUIREMENTS,
  passwordRequirementCheckers,
} from "@/types/authFormSchema";

interface PasswordRequirementsMessageProps {
  password: string;
  className?: string;
}

const REQUIREMENTS = [
  {
    key: "minLength",
    checker: passwordRequirementCheckers.minLength,
    label: `At least ${PASSWORD_REQUIREMENTS.minLength} characters`,
  },
  {
    key: "specialChars",
    checker: passwordRequirementCheckers.specialChars,
    label: "Special characters",
  },
  {
    key: "uppercase",
    checker: passwordRequirementCheckers.uppercase,
    label: "Uppercase letters",
  },
  {
    key: "lowercase",
    checker: passwordRequirementCheckers.lowercase,
    label: "Lowercase letters",
  },
  {
    key: "numbers",
    checker: passwordRequirementCheckers.numbers,
    label: "Numbers",
  },
];

export const PasswordRequirementsMessage = ({
  password,
  className = "",
}: PasswordRequirementsMessageProps) => {
  const hasPasswordInput = password.length > 0;
  if (!hasPasswordInput) {
    return null;
  }
  const results = REQUIREMENTS.map((req) => ({
    ...req,
    isMet: req.checker(password),
  }));
  const metCount = results.filter((r) => r.isMet).length;
  const allRequirementsMet = metCount === REQUIREMENTS.length;

  return (
    <div className={className}>
      <div
        className={`rounded-xl border p-3 ${
          allRequirementsMet
            ? "border-system-success bg-system-success/10"
            : "border-red-200 bg-red-50"
        }`}
        role="region"
        aria-label="Password requirements status"
      >
        {allRequirementsMet ? (
          <div className="flex items-center gap-2">
            <CheckCircle
              className="text-system-success h-4 w-4 shrink-0"
              aria-hidden="true"
            />
            <p className="text-system-success text-xs leading-tight font-medium">
              Password meets all requirements
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <AlertCircle
                className="h-4 w-4 shrink-0 text-red-600"
                aria-hidden="true"
              />
              <p className="text-xs leading-tight font-medium text-red-700">
                Password must include:
              </p>
            </div>
            <ul
              className="ml-6 flex flex-col gap-0.5"
              aria-label="Password requirements"
            >
              {results.map((req) => (
                <li
                  key={req.key}
                  className="flex items-center gap-2 text-xs leading-tight"
                >
                  <div className="flex items-center gap-2">
                    <div
                      className={`h-2 w-2 shrink-0 rounded-full ${
                        req.isMet ? "bg-system-success" : "bg-red-400"
                      }`}
                      aria-hidden="true"
                    />
                    <span
                      className={`${req.isMet ? "text-system-success" : "text-red-700"}`}
                      aria-label={`${req.label} ${req.isMet ? "satisfied" : "required"}`}
                    >
                      {req.label}
                    </span>
                  </div>
                  <span className="sr-only">
                    {req.isMet ? "Requirement met" : "Requirement not met"}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
};
