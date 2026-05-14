---
name: typescript
description: >
  TypeScript strict patterns and best practices.
  Trigger: When implementing or refactoring TypeScript in .ts/.tsx (types, interfaces, generics, const maps, type guards, removing any, tightening unknown).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke: "Writing TypeScript types/interfaces"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Const Types Pattern (REQUIRED)

```typescript
// ✅ ALWAYS: Create const object first, then extract type
const STATUS = {
  ACTIVE: "active",
  INACTIVE: "inactive",
  PENDING: "pending",
} as const;

type Status = (typeof STATUS)[keyof typeof STATUS];

// ❌ NEVER: Direct union types
type Status = "active" | "inactive" | "pending";
```

**Why?** Single source of truth, runtime values, autocomplete, easier refactoring.

## Flat Interfaces (REQUIRED)

```typescript
// ✅ ALWAYS: One level depth, nested objects → dedicated interface
interface UserAddress {
  street: string;
  city: string;
}

interface User {
  id: string;
  name: string;
  address: UserAddress;  // Reference, not inline
}

interface Admin extends User {
  permissions: string[];
}

// ❌ NEVER: Inline nested objects
interface User {
  address: { street: string; city: string };  // NO!
}
```

## Never Use `any`

```typescript
// ✅ Use unknown for truly unknown types
function parse(input: unknown): User {
  if (isUser(input)) return input;
  throw new Error("Invalid input");
}

// ✅ Use generics for flexible types
function first<T>(arr: T[]): T | undefined {
  return arr[0];
}

// ❌ NEVER
function parse(input: any): any { }
```

## Utility Types

```typescript
Pick<User, "id" | "name">     // Select fields
Omit<User, "id">              // Exclude fields
Partial<User>                 // All optional
Required<User>                // All required
Readonly<User>                // All readonly
Record<string, User>          // Object type
Extract<Union, "a" | "b">     // Extract from union
Exclude<Union, "a">           // Exclude from union
NonNullable<T | null>         // Remove null/undefined
ReturnType<typeof fn>         // Function return type
Parameters<typeof fn>         // Function params tuple
```

## Type Guards

```typescript
function isUser(value: unknown): value is User {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    "name" in value
  );
}
```

## Coupled Optional Props (REQUIRED)

Do not model semantically coupled props as independent optionals — this allows invalid half-states that compile but break at runtime. Use discriminated unions with `never` to make invalid combinations impossible.

```typescript
// ❌ BEFORE: Independent optionals — half-states allowed
interface PaginationProps {
  onPageChange?: (page: number) => void;
  pageSize?: number;
  currentPage?: number;
}

// ✅ AFTER: Discriminated union — shape is all-or-nothing
type ControlledPagination = {
  controlled: true;
  currentPage: number;
  pageSize: number;
  onPageChange: (page: number) => void;
};

type UncontrolledPagination = {
  controlled: false;
  currentPage?: never;
  pageSize?: never;
  onPageChange?: never;
};

type PaginationProps = ControlledPagination | UncontrolledPagination;
```

**Key rule:** If two or more props are only meaningful together, they belong to the same discriminated union branch. Mixing them as independent optionals shifts correctness responsibility from the type system to runtime guards.

## Import Types

```typescript
import type { User } from "./types";
import { createUser, type Config } from "./utils";
```
