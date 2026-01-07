
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: nextjs-15
description: Next.js 15 App Router patterns. Server Components, Server Actions, streaming, route groups.
license: MIT
---

## When to use this skill

Use this skill for Next.js 15+ projects with App Router.

## Critical Rules

### App Router File Conventions

\`\`\`
app/
├── layout.tsx          # Root layout (required)
├── page.tsx            # Home page (/)
├── loading.tsx         # Loading UI (Suspense boundary)
├── error.tsx           # Error boundary
├── not-found.tsx       # 404 page
├── (auth)/             # Route group (no URL impact)
│   ├── login/page.tsx  # /login
│   └── signup/page.tsx # /signup
├── (dashboard)/        # Another route group
│   └── settings/
│       └── page.tsx    # /settings
├── api/                # API routes
│   └── route.ts        # API handler
└── _components/        # Private folder (not routed)
    └── Header.tsx
\`\`\`

### Server Components (Default)

\`\`\`typescript
// app/users/page.tsx - Server Component by default
export default async function UsersPage() {
  // Direct database/API access
  const users = await db.users.findMany();

  return (
    <div>
      <h1>Users</h1>
      {users.map(user => (
        <UserCard key={user.id} user={user} />
      ))}
    </div>
  );
}
\`\`\`

### Server Actions

\`\`\`typescript
// app/actions/users.ts
"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

export async function createUser(formData: FormData) {
  const name = formData.get("name") as string;
  const email = formData.get("email") as string;

  // Validate
  if (!name || !email) {
    return { error: "Name and email required" };
  }

  // Create
  await db.users.create({ data: { name, email } });

  // Revalidate and redirect
  revalidatePath("/users");
  redirect("/users");
}

// Usage in component
import { createUser } from "@/app/actions/users";

export function CreateUserForm() {
  return (
    <form action={createUser}>
      <input name="name" required />
      <input name="email" type="email" required />
      <button type="submit">Create</button>
    </form>
  );
}
\`\`\`

### Data Fetching Patterns

\`\`\`typescript
// Parallel fetching
async function Page() {
  const [users, posts] = await Promise.all([
    getUsers(),
    getPosts(),
  ]);
  return <Dashboard users={users} posts={posts} />;
}

// Sequential fetching (when dependent)
async function Page({ params }) {
  const user = await getUser(params.id);
  const posts = await getPostsByAuthor(user.id);
  return <Profile user={user} posts={posts} />;
}

// Streaming with Suspense
async function Page() {
  return (
    <div>
      <h1>Dashboard</h1>
      <Suspense fallback={<Loading />}>
        <SlowComponent />
      </Suspense>
    </div>
  );
}
\`\`\`

### Route Handlers (API)

\`\`\`typescript
// app/api/users/route.ts
import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const query = searchParams.get("query");

  const users = await db.users.findMany({
    where: query ? { name: { contains: query } } : undefined,
  });

  return NextResponse.json(users);
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const user = await db.users.create({ data: body });
  return NextResponse.json(user, { status: 201 });
}

// Dynamic route: app/api/users/[id]/route.ts
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const user = await db.users.findUnique({ where: { id: params.id } });
  if (!user) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  return NextResponse.json(user);
}
\`\`\`

### Middleware

\`\`\`typescript
// middleware.ts (root level)
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  // Check auth
  const token = request.cookies.get("token");

  if (!token && request.nextUrl.pathname.startsWith("/dashboard")) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/api/:path*"],
};
\`\`\`

### Metadata

\`\`\`typescript
// Static metadata
export const metadata = {
  title: "My App",
  description: "App description",
};

// Dynamic metadata
export async function generateMetadata({ params }) {
  const product = await getProduct(params.id);
  return {
    title: product.name,
    description: product.description,
  };
}
\`\`\`

### server-only Package

\`\`\`typescript
// lib/db.ts - Mark as server-only
import "server-only";

export async function getUsers() {
  // This will error if imported in client component
  return db.users.findMany();
}
\`\`\`

## Keywords
nextjs, next.js, app router, server components, server actions, streaming
`;

export default tool({
  description: SKILL,
  args: {
    topic: tool.schema.string().describe("Topic: server-actions, data-fetching, route-handlers, middleware, metadata"),
  },
  async execute(args) {
    const topic = args.topic.toLowerCase();

    if (topic.includes("action")) {
      return `
## Server Actions

\`\`\`typescript
// app/actions.ts
"use server";

import { revalidatePath } from "next/cache";

export async function createItem(formData: FormData) {
  const name = formData.get("name") as string;

  await db.items.create({ data: { name } });
  revalidatePath("/items");
}

// Usage
<form action={createItem}>
  <input name="name" />
  <button type="submit">Create</button>
</form>
\`\`\`
      `.trim();
    }

    if (topic.includes("fetch") || topic.includes("data")) {
      return `
## Data Fetching

\`\`\`typescript
// Server Component - direct async
async function Page() {
  const data = await fetch("https://api.example.com/data");
  return <Component data={data} />;
}

// Parallel
const [a, b] = await Promise.all([getA(), getB()]);

// Streaming
<Suspense fallback={<Loading />}>
  <SlowComponent />
</Suspense>
\`\`\`
      `.trim();
    }

    if (topic.includes("route") || topic.includes("api")) {
      return `
## Route Handlers

\`\`\`typescript
// app/api/items/route.ts
import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  const items = await db.items.findMany();
  return NextResponse.json(items);
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const item = await db.items.create({ data: body });
  return NextResponse.json(item, { status: 201 });
}
\`\`\`
      `.trim();
    }

    return `
## Next.js 15 Quick Reference

1. **Server Components** by default (no directive)
2. **"use client"** only for interactivity
3. **Server Actions** with "use server" for mutations
4. **Route groups** (folder) for organization without URL impact
5. **Streaming** with Suspense for better UX
6. **server-only** package to prevent client imports

Topics: server-actions, data-fetching, route-handlers, middleware, metadata
    `.trim();
  },
})
