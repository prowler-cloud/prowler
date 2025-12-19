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
