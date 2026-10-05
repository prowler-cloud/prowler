import { describe, expect, it } from "vitest";

import { orderRolesAdminFirst } from "./order-roles";

describe("orderRolesAdminFirst", () => {
  it("moves the admin role to the front and keeps the rest in order", () => {
    const roles = [
      { id: "1", name: "member" },
      { id: "2", name: "Admin" },
      { id: "3", name: "auditor" },
    ];

    expect(orderRolesAdminFirst(roles).map((role) => role.name)).toEqual([
      "Admin",
      "member",
      "auditor",
    ]);
  });

  it("leaves the list untouched when there is no admin role", () => {
    const roles = [
      { id: "1", name: "member" },
      { id: "2", name: "auditor" },
    ];

    expect(orderRolesAdminFirst(roles)).toEqual(roles);
    expect(orderRolesAdminFirst(roles)).not.toBe(roles);
  });
});
