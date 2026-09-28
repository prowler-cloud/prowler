import type { CellContext } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import type { ReactElement, ReactNode } from "react";
import { describe, expect, expectTypeOf, it, vi } from "vitest";

import type { UserProps } from "@/types";
import type { UserSignInMethod } from "@/types/users";

vi.mock("@/components/shadcn", () => ({
  Badge: ({ children, variant }: { children: ReactNode; variant?: string }) => (
    <span data-variant={variant}>{children}</span>
  ),
}));

vi.mock("@/components/shadcn/entities", () => ({
  DateWithTime: () => <time />,
}));

vi.mock("@/components/shadcn/table", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: () => false,
}));

vi.mock("./data-table-row-actions", () => ({
  DataTableRowActions: () => null,
}));

import { getColumnsUser } from "./column-users";

const getColumnId = (column: ReturnType<typeof getColumnsUser>[number]) => {
  if ("accessorKey" in column) {
    return column.accessorKey;
  }

  return column.id;
};

const renderSignInMethodsCell = (signInMethods?: UserSignInMethod[]) => {
  const signInMethodsColumn = getColumnsUser(true).find(
    (column) => getColumnId(column) === "sign_in_methods",
  );

  if (typeof signInMethodsColumn?.cell !== "function") {
    throw new Error("Sign-in methods cell is not configured");
  }

  const user = {
    attributes: {
      sign_in_methods: signInMethods,
    },
  } as unknown as UserProps;

  return render(
    signInMethodsColumn.cell({
      row: { original: user },
    } as CellContext<UserProps, unknown>) as ReactElement,
  );
};

describe("getColumnsUser", () => {
  it("should only allow domains on SAML sign-in methods", () => {
    // Given
    type NonSamlMethodWithDomain = {
      method: "google";
      domain: string;
    };
    type SamlMethodWithoutDomain = {
      method: "saml";
    };

    // When
    const nonSamlMethod = expectTypeOf<NonSamlMethodWithDomain>();
    const samlMethod = expectTypeOf<SamlMethodWithoutDomain>();

    // Then
    nonSamlMethod.not.toExtend<UserSignInMethod>();
    samlMethod.toExtend<UserSignInMethod>();
  });

  it("should include non-sortable sign-in methods only in Cloud", () => {
    // Given
    const signInMethodsColumnId = "sign_in_methods";

    // When
    const cloudColumns = getColumnsUser(true);
    const ossColumns = getColumnsUser(false);

    // Then
    expect(cloudColumns.map(getColumnId)).toContain(signInMethodsColumnId);
    expect(ossColumns.map(getColumnId)).not.toContain(signInMethodsColumnId);

    const signInMethodsColumn = cloudColumns.find(
      (column) => getColumnId(column) === signInMethodsColumnId,
    );
    expect(signInMethodsColumn?.enableSorting).toBe(false);
    expect(signInMethodsColumn?.enableColumnFilter).toBe(false);
  });

  it("should render every sign-in method in API order", () => {
    // Given
    const signInMethods: UserSignInMethod[] = [
      { method: "email_password" },
      { method: "google" },
      { method: "github" },
      { method: "saml" },
      { method: "saml", domain: "acme.com" },
      { method: "saml", domain: "subsidiary.com" },
      { method: "partner_sso" },
    ];

    // When
    renderSignInMethodsCell(signInMethods);

    // Then
    const renderedMethods = screen.getAllByRole("listitem");
    expect(renderedMethods.map((item) => item.textContent)).toEqual([
      "Email/password",
      "Google",
      "GitHub",
      "SAML",
      "SAML (acme.com)",
      "SAML (subsidiary.com)",
      "Partner SSO",
    ]);
    expect(
      renderedMethods.map(
        (item) => item.querySelector('[data-variant="tag"]') !== null,
      ),
    ).toEqual(Array.from({ length: signInMethods.length }, () => true));
  });

  it.each([
    ["missing", undefined],
    ["empty", []],
  ] as const)(
    "should render a hyphen when sign-in methods are %s",
    (_state, signInMethods) => {
      // Given
      const methods = signInMethods as UserSignInMethod[] | undefined;

      // When
      renderSignInMethodsCell(methods);

      // Then
      expect(screen.getByText("-")).toBeVisible();
    },
  );
});
