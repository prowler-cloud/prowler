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

**Note:** The `pnpm install` command does not configure Git hooks automatically. To install prek hooks for code quality checks, run one of the following:

From `ui/`:

```bash
pnpm run setup:hooks
```

From the monorepo root:

```bash
cd ui && pnpm run setup:hooks
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

## Git Hooks

The UI uses [prek](https://github.com/j178/prek) for pre-commit checks, configured in [`.pre-commit-config.yaml`](.pre-commit-config.yaml). Git hook setup is opt-in so package installs do not mutate shared git state automatically. To install or re-install manually:

From `ui/`:

```bash
pnpm run setup:hooks
```

From the monorepo root:

```bash
cd ui && pnpm run setup:hooks
```

On each commit, prek runs Prettier and ESLint against the staged files, plus a project-wide TypeScript check and the unit tests related to the staged changes. The full Next.js build runs in CI, not on commit.
