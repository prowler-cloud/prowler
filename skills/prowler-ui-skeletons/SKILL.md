---
name: prowler-ui-skeletons
description: "Trigger: skeleton, loading state, Suspense fallback, content reveal, shimmer. Use Prowler shadcn skeletons correctly."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke:
    - "Creating/modifying skeletons"
    - "Creating/modifying loading states"
    - "Adding Suspense fallbacks"
---

## Activation Contract

Use this skill before creating or modifying any Prowler UI skeleton, loading placeholder, Suspense fallback, or loading-to-content transition.

## Hard Rules

- Prefer shadcn `Skeleton` from `@/components/shadcn`; do not add new HeroUI skeletons.
- Do not mix HeroUI and shadcn inside the same new loading surface.
- Keep scanner/shimmer behavior centralized in shadcn `Skeleton`; never duplicate scanner CSS in feature files.
- For Suspense data loading, wrap the boundary with `SkeletonBoundary` so fallback removal and real content reveal are paired.
- For client-state loading (`isLoading`, drawers, modals, expanded rows), add a reveal wrapper around the resolved content, not around the skeleton.
- Respect `motion-reduce`; every animation must degrade to no transform/transition.
- Preserve layout stability: skeleton dimensions must match the final content as closely as practical.
- Do not migrate legacy/HeroUI skeletons unless the task explicitly includes that migration.

## Decision Gates

| Situation | Action |
| --- | --- |
| Page/server data with `Suspense` fallback | Use `SkeletonBoundary` with the skeleton fallback. |
| Nested Suspense inside tab/chart content | Use `SkeletonBoundary` unless the fallback is legacy/HeroUI. |
| Client state swaps skeleton to content | Keep shadcn `Skeleton`; wrap resolved content with `SkeletonContentReveal` or an equivalent shared reveal. |
| Existing HeroUI skeleton | Leave unchanged unless migration is explicitly requested. |
| Text-only `Loading...` fallback | Replace only if the requested scope includes that surface. |

## Execution Steps

1. Identify whether the skeleton is shadcn, HeroUI legacy, or text-only fallback.
2. If shadcn + Suspense, use `SkeletonBoundary` instead of raw `Suspense`.
3. If shadcn + client state, keep the skeleton fallback and reveal only the loaded content.
4. Verify reduced-motion classes remain present.
5. Add or update focused tests when changing shared skeleton primitives or reusable boundaries.

## Output Contract

Report:
- Which loading surfaces changed.
- Whether each surface is Suspense-boundary or client-state loading.
- Which legacy/HeroUI skeletons were intentionally left untouched.
- Test/typecheck evidence when implementation changes are made.

## References

- `ui/components/shadcn/skeleton/skeleton.tsx`
- `ui/components/shadcn/skeleton/skeleton-boundary.tsx`
- `ui/components/shadcn/skeleton/skeleton-content-reveal.tsx`
