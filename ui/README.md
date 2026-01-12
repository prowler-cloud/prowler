# Description

This repository hosts the UI component for Prowler, providing a user-friendly web interface to interact seamlessly with Prowler's features.


## 🚀 Production deployment
### Docker deployment
#### Clone the repository
```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```
#### Build the Docker image
```bash
docker build -t prowler-cloud/ui . --target prod
```
#### Run the Docker container
```bash
docker run -p 3000:3000 prowler-cloud/ui
```

### Local deployment
#### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```

#### Build the project

```bash
pnpm run build
```

#### Run the production server

```bash
pnpm start
```

## 🧪 Development deployment
### Docker deployment
#### Clone the repository
```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```
#### Build the Docker image
```bash
docker build -t prowler-cloud/ui . --target dev
```
#### Run the Docker container
```bash
docker run -p 3000:3000 prowler-cloud/ui
```

### Local deployment
#### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```

#### Install dependencies

```bash
pnpm install
```

**Note:** The `pnpm install` command will automatically configure Git hooks for code quality checks. If you experience issues, you can manually configure them:

```bash
git config core.hooksPath "ui/.husky"
```

#### Run the development server

```bash
pnpm run dev
```

## Technologies Used

- [Next.js 14](https://nextjs.org/docs/getting-started)
- [NextUI v2](https://nextui.org/)
- [Tailwind CSS](https://tailwindcss.com/)
- [Tailwind Variants](https://tailwind-variants.org)
- [TypeScript](https://www.typescriptlang.org/)
- [Framer Motion](https://www.framer.com/motion/)
- [next-themes](https://github.com/pacocoursey/next-themes)

## Configuration

### Next.js Configuration (`next.config.js`)

The Next.js configuration includes several important settings:

#### Security Headers

- **Content-Security-Policy (CSP)**: Restricts resource loading to prevent XSS attacks
- **X-Content-Type-Options**: Set to `nosniff` to prevent MIME type sniffing
- **Referrer-Policy**: Set to `strict-origin-when-cross-origin`

#### Server Actions

Server actions are configured with an extended body size limit to support large scan file imports:

```javascript
experimental: {
  serverActions: {
    bodySizeLimit: "1gb",  // Supports importing large scan result files
  },
}
```

This allows importing Prowler CLI scan results (OCSF JSON or CSV format) up to 1GB in size.

#### Sentry Integration

Error tracking is automatically enabled when Sentry environment variables are configured:

| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_SENTRY_DSN` | Client-side Sentry DSN |
| `SENTRY_DSN` | Server-side Sentry DSN |
| `SENTRY_ORG` | Sentry organization slug |
| `SENTRY_PROJECT` | Sentry project slug |
| `SENTRY_AUTH_TOKEN` | Auth token for source map uploads |

#### Production Build

In production (`NODE_ENV=production`), the build uses standalone output mode for optimized Docker deployments. This is automatically disabled in CI environments.

## Git Hooks & Code Review

This project uses Git hooks to maintain code quality. When you commit changes to TypeScript/JavaScript files, the pre-commit hook can optionally validate them against our coding standards using Claude Code.

### Enabling Code Review

To enable automatic code review on commits, add this to your `.env` file in the project root:

```bash
CODE_REVIEW_ENABLED=true
```

When enabled, the hook will:
- ✅ Validate your staged changes against `AGENTS.md` standards
- ✅ Check for common issues (any types, incorrect imports, styling violations, etc.)
- ✅ Block commits that don't comply with the standards
- ✅ Provide helpful feedback on how to fix issues

### Disabling Code Review

To disable code review (faster commits, useful for quick iterations):

```bash
CODE_REVIEW_ENABLED=false
```

Or remove the variable from your `.env` file.

### Requirements

- [Claude Code CLI](https://github.com/anthropics/claude-code) installed and authenticated
- `.env` file in the project root with `CODE_REVIEW_ENABLED` set

### Troubleshooting

If hooks aren't running after commits:

```bash
# Verify hooks are configured
git config --get core.hooksPath  # Should output: ui/.husky

# Reconfigure if needed
git config core.hooksPath "ui/.husky"
```
