# shadcn Components

This directory contains all shadcn/ui based components for the Prowler application.

## Directory Structure

Example of a custom component:

```
shadcn/
├── card/
│   ├── base-card/
│   │   ├── base-card.tsx
│   ├── card/
│   │   ├── card.tsx
│   └── resource-stats-card/
│       ├── resource-stats-card.tsx
│       ├── resource-stats-card.example.tsx
├── tabs/
│   ├── tabs.tsx                # Base tab components
│   ├── generic-tabs.tsx        # Generic reusable tabs with lazy loading
├── index.ts                    # Barrel exports
└── README.md
```

## Usage

All shadcn components can be imported from `@/components/shadcn`:

```tsx
import { Card, CardHeader, CardContent } from "@/components/shadcn";
import { ResourceStatsCard } from "@/components/shadcn";
import { GenericTabs, type TabItem } from "@/components/shadcn";
```

### GenericTabs Component

The `GenericTabs` component provides a flexible, lazy-loaded tabs interface. Content is only rendered when the tab is active, improving performance.

**Basic Example:**

```tsx
import { lazy } from "react";
import { GenericTabs, type TabItem } from "@/components/shadcn";

const OverviewContent = lazy(() => import("./OverviewContent"));
const DetailsContent = lazy(() => import("./DetailsContent"));

const tabs: TabItem[] = [
  {
    id: "overview",
    label: "Overview",
    content: OverviewContent,
  },
  {
    id: "details",
    label: "Details",
    content: DetailsContent,
  },
];

export function MyComponent() {
  return <GenericTabs tabs={tabs} defaultTabId="overview" />;
}
```

**With Icons and Props:**

```tsx
import { Eye, Settings } from "lucide-react";
import { GenericTabs, type TabItem } from "@/components/shadcn";

const tabs: TabItem[] = [
  {
    id: "view",
    label: "View",
    icon: <Eye size={16} />,
    content: ViewContent,
    contentProps: { data: myData },
  },
  {
    id: "config",
    label: "Config",
    icon: <Settings size={16} />,
    content: ConfigContent,
  },
];

export function MyComponent() {
  return (
    <GenericTabs
      tabs={tabs}
      defaultTabId="view"
      onTabChange={(tabId) => console.log("Active tab:", tabId)}
    />
  );
}
```

**Props:**

- `tabs` - Array of `TabItem` objects
- `defaultTabId` - Initial active tab ID (defaults to first tab)
- `className` - Wrapper class
- `listClassName` - TabsList class
- `triggerClassName` - TabsTrigger class
- `contentClassName` - TabsContent class
- `onTabChange` - Callback fired when tab changes

## Adding New shadcn Components

When adding new shadcn components using the CLI:

```bash
npx shadcn@latest add [component-name]
```

The component will be automatically added to this directory due to the configuration in `components.json`:

```json
{
  "aliases": {
    "ui": "@/components/shadcn"
  }
}
```

## Component Guidelines

1. **shadcn base components** - Use as-is from shadcn/ui (e.g., `card.tsx`)
2. **Custom components built on shadcn** - Create in subdirectories (e.g., `resource-stats-card/`)
3. **CVA variants** - Use Class Variance Authority for type-safe variants
4. **Theme support** - Include `dark:` classes for dark/light theme compatibility
5. **TypeScript** - Always export types and use proper typing

## Resources

- [shadcn/ui Documentation](https://ui.shadcn.com)
- [CVA Documentation](https://cva.style/docs)
- [Tailwind CSS Documentation](https://tailwindcss.com/docs)
