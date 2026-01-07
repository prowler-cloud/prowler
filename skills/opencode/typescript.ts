
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: typescript
description: TypeScript strict patterns and best practices. Const types, flat interfaces, utility types, strict mode.
license: MIT
---

## When to use this skill

Use this skill for TypeScript best practices in any project.

## Critical Rules

### Const Types Pattern (REQUIRED)

\`\`\`typescript
// ✅ ALWAYS: Create const object first, then extract type
const STATUS = {
  ACTIVE: "active",
  INACTIVE: "inactive",
  PENDING: "pending",
} as const;

type Status = (typeof STATUS)[keyof typeof STATUS];
// Result: "active" | "inactive" | "pending"

// ❌ NEVER: Direct union types
type Status = "active" | "inactive" | "pending";
\`\`\`

**Why?** Const objects provide:
- Single source of truth
- Runtime values for comparisons
- Autocomplete in IDE
- Easier refactoring

### Flat Interfaces (REQUIRED)

\`\`\`typescript
// ✅ ALWAYS: One level depth, nested objects → dedicated interface
interface UserAddress {
  street: string;
  city: string;
  zipCode: string;
}

interface UserProfile {
  bio: string;
  avatar: string;
}

interface User {
  id: string;
  name: string;
  address: UserAddress;
  profile: UserProfile;
}

// Extend for variations
interface Admin extends User {
  permissions: string[];
  department: string;
}

// ❌ NEVER: Inline nested objects
interface User {
  id: string;
  address: { street: string; city: string };  // NO!
  profile: { bio: string; avatar: string };   // NO!
}
\`\`\`

### Strict Mode

\`\`\`json
// tsconfig.json
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noImplicitOverride": true
  }
}
\`\`\`

### Never Use \`any\`

\`\`\`typescript
// ✅ Use unknown for truly unknown types
function parse(input: unknown): User {
  if (isUser(input)) return input;
  throw new Error("Invalid input");
}

// ✅ Use generics for flexible types
function first<T>(arr: T[]): T | undefined {
  return arr[0];
}

// ❌ NEVER: any
function parse(input: any): any { }  // NO!
\`\`\`

### Utility Types

\`\`\`typescript
// Pick specific fields
type UserPreview = Pick<User, "id" | "name">;

// Omit fields
type UserWithoutId = Omit<User, "id">;

// Make all optional
type PartialUser = Partial<User>;

// Make all required
type RequiredUser = Required<User>;

// Make readonly
type ReadonlyUser = Readonly<User>;

// Record for objects
type UserMap = Record<string, User>;

// Extract from union
type ActiveStatus = Extract<Status, "active" | "pending">;

// Exclude from union
type InactiveStatus = Exclude<Status, "active">;
\`\`\`

### Type Guards

\`\`\`typescript
// Type predicate
function isUser(value: unknown): value is User {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    "name" in value
  );
}

// Discriminated unions
interface SuccessResult {
  status: "success";
  data: User;
}

interface ErrorResult {
  status: "error";
  error: string;
}

type Result = SuccessResult | ErrorResult;

function handleResult(result: Result) {
  if (result.status === "success") {
    // TypeScript knows result.data exists
    console.log(result.data);
  } else {
    // TypeScript knows result.error exists
    console.log(result.error);
  }
}
\`\`\`

### Import Types

\`\`\`typescript
// ✅ Use type imports for types only
import type { User, UserAddress } from "./types";
import { createUser } from "./utils";

// ✅ Inline type import
import { createUser, type User } from "./module";
\`\`\`

## Keywords
typescript, ts, types, interfaces, generics, strict mode, utility types
`;

export default tool({
  description: SKILL,
  args: {
    topic: tool.schema.string().describe("Topic: const-types, interfaces, utility-types, type-guards, strict"),
  },
  async execute(args) {
    const topic = args.topic.toLowerCase();

    if (topic.includes("const") || topic.includes("union")) {
      return `
## Const Types Pattern

\`\`\`typescript
// 1. Define const object
const STATUS = {
  ACTIVE: "active",
  INACTIVE: "inactive",
  PENDING: "pending",
} as const;

// 2. Extract type
type Status = (typeof STATUS)[keyof typeof STATUS];

// 3. Use both
function setStatus(status: Status) {
  if (status === STATUS.ACTIVE) {
    // ...
  }
}

// Works with any shape:
const ROLES = { ADMIN: "admin", USER: "user" } as const;
type Role = (typeof ROLES)[keyof typeof ROLES];

const SIZES = { SM: 1, MD: 2, LG: 3 } as const;
type Size = (typeof SIZES)[keyof typeof SIZES];
\`\`\`
      `.trim();
    }

    if (topic.includes("interface")) {
      return `
## Flat Interface Pattern

\`\`\`typescript
// ✅ CORRECT: Separate interfaces, max 1 level depth
interface Address {
  street: string;
  city: string;
}

interface User {
  id: string;
  name: string;
  address: Address;  // Reference, not inline
}

interface Admin extends User {
  permissions: string[];
}

// ❌ WRONG: Nested inline objects
interface User {
  address: { street: string; city: string };  // NO!
}
\`\`\`
      `.trim();
    }

    if (topic.includes("utility")) {
      return `
## TypeScript Utility Types

\`\`\`typescript
type User = { id: string; name: string; email: string; };

Pick<User, "id" | "name">     // { id: string; name: string; }
Omit<User, "id">              // { name: string; email: string; }
Partial<User>                 // All fields optional
Required<User>                // All fields required
Readonly<User>                // All fields readonly
Record<string, User>          // { [key: string]: User }
Extract<"a" | "b", "a">       // "a"
Exclude<"a" | "b", "a">       // "b"
NonNullable<string | null>    // string
ReturnType<typeof fn>         // Return type of function
Parameters<typeof fn>         // Parameters as tuple
\`\`\`
      `.trim();
    }

    return `
## TypeScript Best Practices

1. **Const Types**: Always create const object first, then extract type
2. **Flat Interfaces**: Max 1 level depth, use separate interfaces
3. **Never any**: Use unknown, generics, or proper types
4. **Type imports**: Use \`import type\` for types only
5. **Strict mode**: Enable all strict options in tsconfig

Use this skill with a specific topic: const-types, interfaces, utility-types, type-guards
    `.trim();
  },
})
