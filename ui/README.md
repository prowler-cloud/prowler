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

**Note:** The `pnpm install` command will automatically configure prek Git hooks for code quality checks. If hooks are not installed, run from the repo root:

```bash
prek install
```

#### Run the development server

```bash
pnpm run dev
```

## Technologies Used

- [Next.js 16](https://nextjs.org/docs/getting-started)
- [shadcn/ui](https://ui.shadcn.com/) (built on [Radix UI](https://www.radix-ui.com/))
- [Tailwind CSS 4](https://tailwindcss.com/)
- [TypeScript](https://www.typescriptlang.org/)
- [Framer Motion](https://www.framer.com/motion/)
- [next-themes](https://github.com/pacocoursey/next-themes)

## Git Hooks

The UI uses [prek](https://github.com/j178/prek) for pre-commit checks, configured in [`.pre-commit-config.yaml`](.pre-commit-config.yaml). `pnpm install` runs the postinstall script that installs hooks automatically. To re-install manually:

```bash
prek install --overwrite
```

On each commit, prek runs Prettier and ESLint against the staged files, plus a project-wide TypeScript check and the unit tests related to the staged changes. The full Next.js build runs in CI, not on commit.
