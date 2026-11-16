---
name: nextjs-16
description: >
  Next.js 16 App Router patterns.
  Trigger: When working in Next.js App Router (app/), Server Components vs Client Components, Server Actions, Route Handlers, proxy.ts, caching/revalidation, Cache Components, and streaming/Suspense.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, ui]
  auto_invoke: "App Router / Server Actions"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## App Router File Conventions

```text
app/
├── layout.tsx           # Root layout (required)
├── page.tsx             # Home page (/)
├── loading.tsx          # Loading UI (Suspense)
├── error.tsx            # Error boundary
├── not-found.tsx        # 404 page
├── (auth)/              # Route group (no URL impact)
│   ├── login/page.tsx   # /login
│   └── signup/page.tsx  # /signup
├── api/
│   └── route.ts         # API handler
└── _components/         # Private folder (not routed)
```

## Next.js 16 Notes

- Prowler UI runs Next.js 16.4 with `reactCompiler: true` and Turbopack (`ui/next.config.js`). Cache Components (`cacheComponents`) is NOT enabled.
- Request APIs are async: `await cookies()`, `await headers()`, and `params` / `searchParams` are `Promise`s in pages, layouts and route handlers.
- Use `proxy.ts` for request-boundary logic. `middleware.ts` is deprecated in Next.js 16. Prowler's `ui/proxy.ts` is `export default auth(async (req) => ...)` (NextAuth v5 wrapper).
- `proxy.ts` runs on the Node.js runtime and cannot be configured for Edge.
- Keep `proxy.ts` matchers narrow. Exclude `api`, static files, and image assets unless the route explicitly needs proxy logic.
- Route Handlers in `app/api/**/route.ts` are the right fit for health checks, webhooks, backend-for-frontend endpoints, and server-only proxy calls.

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
"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

export async function createUser(formData: FormData) {
  const name = formData.get("name") as string;

  await db.users.create({ data: { name } });

  revalidatePath("/users");
  redirect("/users");
}
```

## Async params / searchParams

```typescript
export default async function Page({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { id } = await params;
  const query = await searchParams;
  return <Detail id={id} query={query} />;
}
```

## Data Fetching

```typescript
async function Page() {
  const [users, posts] = await Promise.all([getUsers(), getPosts()]);

  return <Dashboard users={users} posts={posts} />;
}

<Suspense fallback={<Loading />}>
  <SlowComponent />
</Suspense>;
```

## Caching and Revalidation

```typescript
import { revalidatePath, revalidateTag } from "next/cache";

export async function refreshDashboard() {
  "use server";

  revalidatePath("/");
  revalidateTag("dashboard", "max"); // Next 16: second arg (cacheLife profile) is required
}
```

- Use `revalidatePath` for route-level invalidation after mutations.
- Use `revalidateTag(tag, profile)` when data fetches share a cache tag across routes. The single-argument form is deprecated in Next.js 16 (see `ui/actions/api-keys/api-keys.ts`).
- With Cache Components enabled, put `"use cache"` only in pure server-side cached functions. Do not cache auth, tenant-scoped, or per-user responses unless the cache key explicitly isolates them.

## Route Handlers (API)

```typescript
// app/api/users/[id]/route.ts
import { NextResponse } from "next/server";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  return NextResponse.json(await db.users.find(id));
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const user = await db.users.update(id, await request.json());
  return NextResponse.json(user);
}
```

## Proxy

```typescript
// proxy.ts (root level)
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function proxy(request: NextRequest) {
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
export const metadata = {
  title: "My App",
  description: "Description",
};

export async function generateMetadata() {
  const product = await getProduct();
  return { title: product.name };
}
```

## server-only Package

```typescript
import "server-only";

export async function getSecretData() {
  return db.secrets.findMany();
}
```
