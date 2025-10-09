# AGENTS.md — Prowler UI Agent Guide

This guide defines how software agents should work within the `ui/` Next.js app. It focuses on safe, incremental frontend changes aligned with the existing architecture and tooling.

## Mission & Scope
- Ship small, high‑impact UI changes with minimal risk.
- Align to current patterns: App Router, Server Components first, consistent styling, strict types.
- Avoid broad refactors, library swaps, or reorganization unless requested.

## Tech Stack (Updated January 2025)
- Next.js 15.5.3 (App Router) with React 19.1.1
- TypeScript 5.5.4
- Styling: Tailwind CSS 4.1.13 + **shadcn/ui** (new components) / HeroUI 2.8.4 (legacy)
- State: Zustand 5.0.8
- Auth: NextAuth.js 5.0.0-beta.29
- Forms/Validation: React Hook Form 7.62.0 + Zod 4.1.11
- AI/Chat: AI SDK 5.0.59 + @ai-sdk/react 2.0.59
- AI Backend: LangChain @langchain/core 0.3.77
- Charts: Recharts 2.15.4
- E2E: Playwright 1.53.2

## Commands
```bash
# install deps
npm install

# dev/build
npm run dev
npm run build
npm start
npm run start:standalone

# quality
npm run typecheck
npm run lint:check
npm run lint:fix
npm run format:check
npm run format:write
npm run healthcheck

# tests (Playwright)
npm run test:e2e
npm run test:e2e:ui
npm run test:e2e:debug
npm run test:e2e:headed
npm run test:e2e:report
npm run test:e2e:install
```

## Project Structure (essentials)
- `app/`: App Router routes and layouts.
  - `(auth)/`: authentication pages.
  - `(prowler)/`: main product areas (scans, findings, compliance, providers, integrations, lighthouse).
  - `api/`: API routes and server actions endpoints as needed.
- `components/`: reusable UI; prefer `components/ui/` primitives and domain folders (e.g., `components/integrations`).
- `actions/`: Server Actions for mutations/data operations.
- `lib/`: utilities and config.
- `types/`: shared TypeScript types.
- `hooks/`: custom React hooks.
- `store/`: Zustand stores.
- `styles/`: global CSS and Tailwind configuration.

## Patterns & Conventions
- Server First: prefer Server Components for data fetching and page assembly; use Client Components only for interactivity/state.
- Server Actions: put mutation logic in `ui/actions`. Validate with Zod. Revalidate caches as needed.
- Types: keep strict types; avoid `any`. Narrow and localize unavoidable exceptions.
- Forms: React Hook Form + Zod resolvers.
- State: centralize cross‑component client state in `store/` (Zustand). Keep local UI state local.
- Styling: **New components should use shadcn/ui with the new Tailwind theme**. Existing components use HeroUI; Tailwind utility classes for layout and customizations. Follow existing color tokens and themes.
- Accessibility: ensure labels, focus management, and keyboard interactions. Prefer Radix primitives where needed.
- Data Fetching: use `fetch` with Next.js caching/revalidation semantics; avoid client fetching when a server boundary is possible.
- Error/Loading: explicit, resilient states. Avoid silent failures.

## File/Code Style
- Component Naming: `PascalCase` for components, `camelCase` for helpers; one component per file where practical.
- Foldering: colocate domain components under domain folders (e.g., `components/integrations/jira/...`).
- Imports: honor alias paths used in the repo (e.g., `@/components/...`). Keep import order consistent with ESLint rules.
- CSS: prefer Tailwind classes; avoid ad‑hoc CSS files unless justified.

## Integrations & Auth
- NextAuth: use server helpers and `server-only` where appropriate. Protect routes through middleware and layout boundaries.
- External Integrations (e.g., Jira, S3, Security Hub): follow existing patterns in `components/integrations/*`. Validate forms with Zod and provide clear user feedback on errors.

## Testing
- Playwright: add/update E2E tests for critical flows you modify.
- Scope: run only the affected specs when iterating. Commit updates to snapshots only with real UI changes.
- Determinism: avoid relying on real external services; mock or stub where possible.

## Performance
- Keep Client Components lean; avoid heavy client‑side logic where a server boundary is possible.
- Use streaming, partial rendering, and skeletons for long operations.
- Memoize expensive client computations; avoid unnecessary re‑renders.

## Quality Gates (before submitting changes)
1. `npm run typecheck` shows 0 new errors.
2. `npm run lint:check` passes or is fixed via `npm run lint:fix`.
3. `npm run format:check` passes or is corrected via `npm run format:write`.
4. Relevant Playwright specs pass locally.
5. UI states (loading, error, empty) are handled.

## Safety & Secrets
- Do not commit secrets or `.env.local` values. Use placeholders in examples.
- Avoid logging sensitive data. Sanitize error messages shown to users.

## When Implementing New UI
- **Use shadcn/ui components with the new Tailwind theme for all new features**.
- Start from existing patterns in the closest domain folder.
- Reuse primitives from `components/ui` (shadcn/ui for new, HeroUI for legacy) and existing composables.
- Add types to `types/` if they're shared; otherwise colocate types near usage.
- Update feature docs and `ui/CHANGELOG.md` when behavior changes.

## Library-Specific Breaking Changes (January 2025)

### Zod v4
- ❌ `.nonempty()` → ✅ `.min(1)` for strings
- ❌ `z.string().email()` → ✅ `z.email()` (top-level function)
- ❌ `z.string().uuid()` → ✅ `z.uuid()` (top-level function)
- ❌ `z.string().url()` → ✅ `z.url()` (top-level function)
- ❌ `required_error` parameter → ✅ `error` parameter
- ❌ `message` parameter → ✅ `error` parameter

### Zustand v5
- ✅ No API changes for basic usage
- ⚠️ `shallow` comparison must use `useShallow` hook from `zustand/react/shallow`
- ⚠️ Selectors must return stable references

### AI SDK v5
- ❌ `Message` type → ✅ `UIMessage` type
- ❌ `message.content` string → ✅ `message.parts` array structure
- ❌ `handleSubmit` / `handleInputChange` → ✅ `sendMessage` with manual state
- ❌ `append()` → ✅ `sendMessage({ text: "..." })`
- ❌ `api: "/endpoint"` → ✅ `transport: new DefaultChatTransport({ api: "/endpoint" })`
- ❌ `LangChainAdapter.toDataStreamResponse()` → ✅ `toUIMessageStream()` from `@ai-sdk/langchain`

## References
- High‑level project guide: `../CLAUDE.md`
- UI guide and quickstart: `./CLAUDE.md`
