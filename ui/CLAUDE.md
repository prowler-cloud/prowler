# Prowler UI Agent Guide

**Comprehensive guide for AI agents and developers working on the Prowler UI Next.js application.**

## Mission & Scope
- Ship small, high-impact UI changes with minimal risk
- Align to current patterns: App Router, Server Components first, consistent styling, strict types
- Avoid broad refactors, library swaps, or reorganization unless requested
- Focus on safe, incremental frontend changes aligned with existing architecture

## Overview
The Prowler UI is a Next.js 15 application providing a modern web interface for the Prowler security platform. It features a comprehensive dashboard for managing cloud security scans, compliance frameworks, and findings across multiple cloud providers.

## Tech Stack (Updated January 2025)
- **Framework**: Next.js 15.5.3 with App Router
- **Runtime**: React 19.1.1
- **Language**: TypeScript 5.5.4
- **Styling**: Tailwind CSS 4.1.13 + **shadcn/ui** (new components) / HeroUI 2.8.4 (legacy)
- **State Management**: Zustand 5.0.8
- **Authentication**: NextAuth.js 5.0.0-beta.29
- **Forms/Validation**: React Hook Form 7.62.0 + Zod 4.1.11
- **AI/Chat**: AI SDK 5.0.59 + @ai-sdk/react 2.0.59
- **AI Backend**: LangChain @langchain/core 0.3.77 + @ai-sdk/langchain 1.0.59
- **Charts**: Recharts 2.15.4
- **Testing**: Playwright 1.53.2
- **Formatter**: Prettier 3.6.2

## Commands

### Development
\`\`\`bash
npm install           # Install dependencies
npm run dev           # Start development server (localhost:3000)
npm run build         # Build for production
npm start             # Start production server
npm run start:standalone  # Start standalone server
\`\`\`

### Code Quality
\`\`\`bash
npm run typecheck     # TypeScript type checking
npm run lint:check    # ESLint checking
npm run lint:fix      # Fix ESLint issues
npm run format:check  # Prettier format checking
npm run format:write  # Format code with Prettier
npm run healthcheck   # Run typecheck + lint together
\`\`\`

### Testing
\`\`\`bash
npm run test:e2e         # Run Playwright tests
npm run test:e2e:ui      # Run tests with UI
npm run test:e2e:debug   # Debug tests
npm run test:e2e:headed  # Run tests in headed mode
npm run test:e2e:report  # Show test report
npm run test:e2e:install # Install Playwright browsers
\`\`\`

## Project Structure

\`\`\`
ui/
├── app/                    # Next.js App Router
│   ├── (auth)/            # Authentication pages (sign-in, sign-up)
│   ├── (prowler)/         # Main application pages
│   │   ├── compliance/    # Compliance frameworks & reports
│   │   ├── findings/      # Security findings & vulnerabilities
│   │   ├── integrations/  # S3, Security Hub integrations
│   │   ├── lighthouse/    # AI-powered security assistant
│   │   ├── providers/     # Cloud provider management
│   │   ├── scans/         # Security scan management
│   │   └── services/      # Cloud services overview
│   └── api/               # API routes & server actions
├── components/            # Reusable UI components
│   ├── ui/               # Base UI components (buttons, forms, etc.)
│   ├── compliance/       # Compliance-specific components
│   ├── findings/         # Findings table & filters
│   ├── providers/        # Provider management UI
│   ├── scans/           # Scan management UI
│   └── integrations/    # Integration configuration
├── actions/              # Server actions (data fetching/mutations)
├── lib/                  # Utility functions & configurations
├── types/               # TypeScript type definitions
├── hooks/               # Custom React hooks
├── store/               # Zustand state management
└── styles/              # Global CSS & Tailwind config
\`\`\`

## Key Features

### Authentication System
- NextAuth.js with multiple providers (credentials, OAuth, SAML)
- Server-side authentication with middleware protection
- Session management and role-based access control

### Cloud Provider Management
- Multi-cloud support (AWS, Azure, GCP, GitHub, K8s, M365)
- Credential management with secure forms
- Connection testing and status monitoring

### Security Scanning
- Real-time scan progress monitoring
- Bulk operations and filtering
- Scheduled scan management
- Download and export capabilities

### Compliance Frameworks
- 36+ compliance frameworks (CIS, NIST, PCI-DSS, etc.)
- Interactive compliance reports with charts
- Requirement-level drill-down views
- Custom compliance mapping

### Lighthouse AI Assistant
- LangChain-powered security chatbot
- Context-aware responses about findings
- Integration with scan data and compliance frameworks

### Findings Management
- Advanced filtering and search
- Mute/unmute functionality with reasons
- Severity-based classification
- Detailed finding analysis

## Patterns & Conventions

### Architecture Principles
- **Server First**: Prefer Server Components for data fetching and page assembly; use Client Components only for interactivity/state
- **Server Actions**: Put mutation logic in \`actions/\`. Validate with Zod. Revalidate caches as needed
- **Types**: Keep strict types; avoid \`any\`. Narrow and localize unavoidable exceptions
- **Forms**: React Hook Form + Zod resolvers
- **State**: Centralize cross-component client state in \`store/\` (Zustand). Keep local UI state local
- **Styling**: **New UI features/pages should use shadcn/ui with the new Tailwind theme**. Existing features/pages should continue using HeroUI for consistency; Tailwind utility classes for layout and customizations
- **Accessibility**: Ensure labels, focus management, and keyboard interactions. Prefer Radix primitives where needed
- **Data Fetching**: Use \`fetch\` with Next.js caching/revalidation semantics; avoid client fetching when server boundary is possible
- **Error/Loading**: Explicit, resilient states. Avoid silent failures

### Component Architecture
\`\`\`typescript
// Prefer server components when possible
export default async function PageComponent() {
  const data = await fetchData();
  return <ClientComponent data={data} />;
}
\`\`\`

### State Management
\`\`\`typescript
// Use Zustand for global state
import { useStore } from "@/hooks/use-store";

const { filters, setFilters } = useStore();
\`\`\`

### Server Actions
\`\`\`typescript
"use server";

export async function updateProvider(formData: FormData) {
  // Validate with Zod
  // Update via API
  // Revalidate cache
}
\`\`\`

### Form Handling
\`\`\`typescript
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

const form = useForm({
  resolver: zodResolver(schema),
});
\`\`\`

## File & Code Style

### Naming & Organization
- **Component Naming**: \`PascalCase\` for components, \`camelCase\` for helpers
- **Foldering**: Colocate domain components under domain folders (e.g., \`components/integrations/jira/\`)
- **Imports**: Honor alias paths (\`@/components/...\`). Keep import order consistent with ESLint rules
- **CSS**: Prefer Tailwind classes; avoid ad-hoc CSS files unless justified

### Import Organization
\`\`\`typescript
// External libraries
import React from "react";
import { Button } from "@heroui/react";

// Internal utilities
import { cn } from "@/lib/utils";

// Types
import type { ComponentProps } from "@/types";
\`\`\`

## Styling Guidelines

### Tailwind + shadcn/ui (New) / HeroUI (Existing)
- **Use shadcn/ui components for new UI features/pages** with the new Tailwind theme
- Existing features/pages should continue using HeroUI (migrated from NextUI) for consistency
- Custom Prowler color palette defined in tailwind.config.js
- Dark/light theme support via next-themes
- Custom shadows and animations for Prowler brand

### Color System
\`\`\`css
/* Prowler Brand Colors */
--prowler-green: #9FD655;
--prowler-midnight: #030921;
--prowler-pale: #f3fcff;

/* Severity Colors */
--critical: #AC1954;
--high: #F31260;
--medium: #FA7315;
--low: #fcd34d;
\`\`\`

## Library-Specific Guidelines

### Zod v4 (Schema Validation)

**Breaking changes from v3:**
- ❌ \`.nonempty()\` → ✅ \`.min(1)\` for strings
- ❌ \`z.string().email()\` → ✅ \`z.email()\` (top-level function)
- ❌ \`z.string().uuid()\` → ✅ \`z.uuid()\` (top-level function)
- ❌ \`z.string().url()\` → ✅ \`z.url()\` (top-level function)
- ❌ \`required_error\` parameter → ✅ \`error\` parameter
- ❌ \`message\` parameter → ✅ \`error\` parameter
- ⚠️ \`.optional()\` type inference changed - fields are now \`T | undefined\` in inferred types

**Example migration:**
\`\`\`typescript
// ❌ Zod v3
const schema = z.object({
  email: z.string().email({ message: "Invalid email" }),
  name: z.string().nonempty("Required"),
  id: z.string().uuid(),
});

// ✅ Zod v4
const schema = z.object({
  email: z.email({ error: "Invalid email" }),
  name: z.string().min(1, "Required"),
  id: z.uuid(),
});
\`\`\`

### Zustand v5 (State Management)

**Breaking changes from v4:**
- ✅ No API changes required for basic usage
- ⚠️ \`shallow\` comparison must use \`useShallow\` hook from \`zustand/react/shallow\`
- ⚠️ Selectors must return stable references to avoid infinite loops
- ⚠️ \`persist\` middleware no longer auto-stores initial state - call \`setState()\` explicitly if needed

**Best practices:**
\`\`\`typescript
import { create } from "zustand";
import { persist } from "zustand/middleware";

const useStore = create(
  persist(
    (set) => ({
      value: 0,
      increment: () => set((state) => ({ value: state.value + 1 })),
    }),
    { name: "my-store" }
  )
);
\`\`\`

### AI SDK v5 (Chat & AI Features)

**Breaking changes from v4:**
- ❌ \`Message\` type → ✅ \`UIMessage\` type
- ❌ \`message.content\` string → ✅ \`message.parts\` array structure
- ❌ \`handleSubmit\` / \`handleInputChange\` → ✅ \`sendMessage\` with manual state
- ❌ \`append()\` → ✅ \`sendMessage({ text: "..." })\`
- ❌ \`api: "/endpoint"\` → ✅ \`transport: new DefaultChatTransport({ api: "/endpoint" })\`
- ❌ \`LangChainAdapter.toDataStreamResponse()\` → ✅ \`toUIMessageStream()\` from \`@ai-sdk/langchain\`

**Example migration:**
\`\`\`typescript
// ❌ AI SDK v4
import { useChat } from "ai";
const { messages, handleSubmit, input, handleInputChange } = useChat({
  api: "/api/chat",
});

// ✅ AI SDK v5
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
const { messages, sendMessage } = useChat({
  transport: new DefaultChatTransport({ api: "/api/chat" }),
});
// Manual input state management required
const [input, setInput] = useState("");
const handleSubmit = (e) => {
  e.preventDefault();
  sendMessage({ text: input });
  setInput("");
};
\`\`\`

**UIMessage structure:**
\`\`\`typescript
// Message parts-based structure
const message: UIMessage = {
  id: "msg-1",
  role: "assistant",
  parts: [
    { type: "text", text: "Hello world" }
  ]
};

// Extract text from parts
const text = message.parts
  .filter(p => p.type === "text")
  .map(p => "text" in p ? p.text : "")
  .join("");
\`\`\`

## Testing

### Playwright E2E Tests
- Add/update E2E tests for critical flows you modify
- Scope: run only affected specs when iterating
- Commit snapshot updates only with real UI changes
- Determinism: avoid relying on real external services; mock or stub where possible

### Component Testing (Future)
- Jest + React Testing Library
- Component unit tests
- Integration tests for complex flows

## Performance

- Keep Client Components lean; avoid heavy client-side logic where server boundary is possible
- Use streaming, partial rendering, and skeletons for long operations
- Memoize expensive client computations; avoid unnecessary re-renders
- App Router with server components
- Image optimization with next/image
- Font optimization with next/font
- Bundle analysis and code splitting

## Security

### Best Practices
- Do not commit secrets or \`.env.local\` values. Use placeholders in examples
- Avoid logging sensitive data. Sanitize error messages shown to users
- Strict CSP headers in next.config.js
- XSS protection and CSRF mitigation
- Secure cookie configuration

### Data Handling
- Client-side validation with Zod
- Server-side sanitization
- Secure credential storage patterns

### Authentication
- NextAuth: use server helpers and \`server-only\` where appropriate
- Protect routes through middleware and layout boundaries
- JWT tokens via NextAuth
- Automatic token refresh
- Protected routes via middleware

## Quality Gates (before submitting changes)

1. \`npm run typecheck\` shows 0 new errors
2. \`npm run lint:check\` passes or is fixed via \`npm run lint:fix\`
3. \`npm run format:check\` passes or is corrected via \`npm run format:write\`
4. Relevant Playwright specs pass locally
5. UI states (loading, error, empty) are handled

## Common Development Tasks

### Adding New Pages
1. Create page component in \`app/(prowler)/\`
2. Add route to navigation in \`lib/menu-list.ts\`
3. Implement required server actions
4. Add proper TypeScript types

### Creating Components
1. **Use shadcn/ui for new UI components that belong to new features/pages**
2. Existing features/pages should continue using HeroUI for consistency
3. Follow established patterns in \`components/ui/\`
4. Implement proper TypeScript interfaces
5. Add to component index files

### Integrating with Backend
1. Create server actions in \`actions/\`
2. Define TypeScript types in \`types/\`
3. Handle loading and error states
4. Implement proper caching strategy

### When Implementing New UI
- **Use shadcn/ui components with the new Tailwind theme for new UI features/pages**
- **For existing features/pages, continue using HeroUI components for consistency**
- Start from existing patterns in the closest domain folder
- Reuse primitives from \`components/ui\` (shadcn/ui for new features, HeroUI for existing) and existing composables
- Add types to \`types/\` if they're shared; otherwise colocate types near usage
- Update feature docs and \`ui/CHANGELOG.md\` when behavior changes

## Environment Configuration

### Required Environment Variables
\`\`\`bash
# Authentication
NEXTAUTH_SECRET=your_secret_here
NEXTAUTH_URL=http://localhost:3000

# API Configuration
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080

# AI Features
OPENAI_API_KEY=your_openai_key
\`\`\`

### Development Setup
1. Copy \`.env.example\` to \`.env.local\`
2. Configure authentication providers
3. Set up API backend connection
4. Install dependencies and start dev server

## Deployment

### Production Build
\`\`\`bash
npm run build          # Build optimized bundle
npm run start          # Start production server
\`\`\`

### Docker Deployment
- Dockerfile available for containerization
- Standalone output for minimal container size
- Health checks via \`/api/health\` endpoint

## Troubleshooting

### Common Issues
1. **TypeScript errors**: Run \`npm run typecheck\`
2. **Lint issues**: Run \`npm run lint:fix\`
3. **Build failures**: Check Next.js build logs
4. **Authentication issues**: Verify NextAuth configuration

### Debug Tools
- Next.js built-in debugger
- React Developer Tools
- Network tab for API debugging
- Lighthouse for performance analysis

## Recent Major Migrations (January 2025)

- ✅ React 18 → 19.1.1 (async components, useActionState)
- ✅ Next.js 14 → 15.5.3 (enhanced App Router)
- ✅ NextUI → HeroUI 2.8.4
- ✅ Zod 3.25.73 → 4.1.11 (breaking: deprecated methods)
- ✅ Zustand 4.5.7 → 5.0.8 (compatible)
- ✅ AI SDK 4.3.16 → 5.0.59 (breaking: new message structure)
- ✅ LangChain updates with new adapter patterns

## References

- **High-level project guide**: \`../CLAUDE.md\` (root Prowler project)
- **UI Changelog**: \`./CHANGELOG.md\`
- **Pull Request**: [#8801](https://github.com/prowler-cloud/prowler/pull/8801) - Latest dependency upgrades
