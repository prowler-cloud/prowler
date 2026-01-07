
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: zod-4
description: Zod 4 schema validation patterns. Breaking changes from v3, new API.
license: MIT
---

## When to use this skill

Use this skill for Zod 4 validation - note breaking changes from v3.

## Breaking Changes from Zod 3

\`\`\`typescript
// ❌ Zod 3 (OLD)
z.string().email()
z.string().uuid()
z.string().url()
z.string().nonempty()
z.object({ name: z.string() }).required_error("Required")

// ✅ Zod 4 (NEW)
z.email()
z.uuid()
z.url()
z.string().min(1)
z.object({ name: z.string() }, { error: "Required" })
\`\`\`

## Basic Schemas

\`\`\`typescript
import { z } from "zod";

// Primitives
const stringSchema = z.string();
const numberSchema = z.number();
const booleanSchema = z.boolean();

// Top-level validators (Zod 4)
const emailSchema = z.email();
const uuidSchema = z.uuid();
const urlSchema = z.url();

// With constraints
const nameSchema = z.string().min(1).max(100);
const ageSchema = z.number().int().positive();
\`\`\`

## Object Schemas

\`\`\`typescript
const userSchema = z.object({
  id: z.uuid(),
  email: z.email({ error: "Invalid email address" }),
  name: z.string().min(1, { error: "Name is required" }),
  age: z.number().int().positive().optional(),
  role: z.enum(["admin", "user", "guest"]),
});

type User = z.infer<typeof userSchema>;

// Parsing
const user = userSchema.parse(data);  // Throws on error
const result = userSchema.safeParse(data);  // { success, data/error }
\`\`\`

## Transformations

\`\`\`typescript
// Transform during parsing
const lowercaseEmail = z.email().transform(email => email.toLowerCase());

// Coercion
const numberFromString = z.coerce.number();  // "42" → 42
const dateFromString = z.coerce.date();
\`\`\`

## React Hook Form Integration

\`\`\`typescript
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

const schema = z.object({
  email: z.email(),
  password: z.string().min(8),
});

const form = useForm({
  resolver: zodResolver(schema),
});
\`\`\`

## Keywords
zod, validation, schema, typescript, forms
`;

export default tool({
  description: SKILL,
  args: {
    topic: tool.schema.string().describe("Topic: migration, objects, arrays, transforms, refinements"),
  },
  async execute(args) {
    const topic = args.topic.toLowerCase();

    if (topic.includes("migrat") || topic.includes("v3") || topic.includes("break")) {
      return `
## Zod 3 → 4 Migration

\`\`\`typescript
// String validators → Top-level
z.string().email()    →  z.email()
z.string().uuid()     →  z.uuid()
z.string().url()      →  z.url()

// nonempty → min(1)
z.string().nonempty() →  z.string().min(1)

// Error messages
{ message: "Error" }  →  { error: "Error" }
{ required_error: "Required" }  →  { error: "Required" }
\`\`\`
      `.trim();
    }

    return `
## Zod 4 Quick Reference

\`\`\`typescript
// Top-level validators (new in v4)
z.email()
z.uuid()
z.url()

// Objects
z.object({
  name: z.string().min(1),
  email: z.email({ error: "Invalid email" }),
});

// Parse
schema.parse(data);       // Throws
schema.safeParse(data);   // { success, data/error }

// Infer type
type T = z.infer<typeof schema>;
\`\`\`
    `.trim();
  },
})
