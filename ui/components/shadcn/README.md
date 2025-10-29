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
├── index.ts                    # Barrel exports
└── README.md
```

## Usage

All shadcn components can be imported from `@/components/shadcn`:

```tsx
import { Card, CardHeader, CardContent } from "@/components/shadcn";
import { ResourceStatsCard } from "@/components/shadcn";
```

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
