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

This project uses Git hooks to maintain code quality:

1. **UI Pre-commit Hook** (`ui/.husky/pre-commit`): Runs healthcheck (typecheck + lint) and build for UI changes
2. **AI Code Review** (`.pre-commit-config.yaml`): Uses [Gentleman Guardian Angel (gga)](https://github.com/Gentleman-Programming/gentleman-guardian-angel) to validate code against `AGENTS-CODE-REVIEW.md` standards

### Enabling AI Code Review

The AI code review runs **after** all formatters and linters have processed the code. To enable it, set in your environment or `.env` file:

```bash
export CODE_REVIEW_ENABLED=true
```

When enabled:

- ✅ Validates staged changes against `AGENTS-CODE-REVIEW.md` standards
- ✅ Reviews both TypeScript (UI) and Python (SDK, API, MCP) files
- ✅ Runs last, after black/isort/prettier have formatted the code
- ✅ Smart caching: skips unchanged files for faster reviews
- ✅ Blocks commits that don't comply with standards

### Disabling AI Code Review

```bash
export CODE_REVIEW_ENABLED=false
```

Or simply don't set the variable (disabled by default).

### Requirements

- **AI CLI**: One of the following must be installed and authenticated:
  - [Claude Code CLI](https://claude.ai/code) (default, recommended)
  - [Gemini CLI](https://github.com/google-gemini/gemini-cli)
  - [Codex CLI](https://www.npmjs.com/package/@openai/codex)
  - [Ollama](https://ollama.ai) (local models)

**Note:** `gga` will be installed automatically on first commit if not present.

### Configuration

The AI code review is configured via `.gga` in the **repository root**:

```bash
PROVIDER="claude"                    # AI provider
FILE_PATTERNS="*.ts,*.tsx,*.js,*.jsx,*.py"
EXCLUDE_PATTERNS="*.test.ts,*.spec.ts,*_test.py,test_*.py,conftest.py,*.d.ts"
RULES_FILE="AGENTS-CODE-REVIEW.md"   # Centralized review rules
STRICT_MODE="true"
```

Available providers: `claude`, `gemini`, `codex`, `ollama:<model>`

### Troubleshooting

If gga installation fails:

```bash
# Homebrew (macOS)
brew install gentleman-programming/tap/gga

# From source (Linux/macOS)
git clone https://github.com/Gentleman-Programming/gentleman-guardian-angel.git /tmp/gga
cd /tmp/gga && ./install.sh
```

To clear the gga cache:

```bash
gga cache clear
```
