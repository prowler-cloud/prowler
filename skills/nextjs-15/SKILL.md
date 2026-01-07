---
name: nextjs-15
description: >
  Next.js 15 App Router patterns.
  Trigger: When working with Next.js - routing, Server Actions, data fetching.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

## App Router File Conventions

```
app/
├── layout.tsx          # Root layout (required)
├── page.tsx            # Home page (/)
├── loading.tsx         # Loading UI (Suspense)
├── error.tsx           # Error boundary
├── not-found.tsx       # 404 page
├── (auth)/             # Route group (no URL impact)
│   ├── login/page.tsx  # /login
│   └── signup/page.tsx # /signup
├── api/
│   └── route.ts        # API handler
└── _components/        # Private folder (not routed)
```

## Server Components (Default)

```typescript
// No directive needed - async by default
export default async function Page() {
  const data = await db.query();
  return <Component data={data} />;
}
```

## Server Actions

```typescript
// app/actions.ts
"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

export async function createUser(formData: FormData) {
  const name = formData.get("name") as string;

  await db.users.create({ data: { name } });

  revalidatePath("/users");
  redirect("/users");
}

// Usage
<form action={createUser}>
  <input name="name" required />
  <button type="submit">Create</button>
</form>
```

## Data Fetching

```typescript
// Parallel
async function Page() {
  const [users, posts] = await Promise.all([
    getUsers(),
    getPosts(),
  ]);
  return <Dashboard users={users} posts={posts} />;
}

// Streaming with Suspense
<Suspense fallback={<Loading />}>
  <SlowComponent />
</Suspense>
```

## Route Handlers (API)

```typescript
// app/api/users/route.ts
import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  const users = await db.users.findMany();
  return NextResponse.json(users);
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const user = await db.users.create({ data: body });
  return NextResponse.json(user, { status: 201 });
}
```

## Middleware

```typescript
// middleware.ts (root level)
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  const token = request.cookies.get("token");

  if (!token && request.nextUrl.pathname.startsWith("/dashboard")) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
```

## Metadata

```typescript
// Static
export const metadata = {
  title: "My App",
  description: "Description",
};

// Dynamic
export async function generateMetadata({ params }) {
  const product = await getProduct(params.id);
  return { title: product.name };
}
```

## server-only Package

```typescript
import "server-only";

// This will error if imported in client component
export async function getSecretData() {
  return db.secrets.findMany();
}
```

## Keywords
nextjs, next.js, app router, server components, server actions, streaming
