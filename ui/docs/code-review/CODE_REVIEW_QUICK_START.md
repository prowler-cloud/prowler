# Code Review - Quick Start

## 3 Pasos para Activar

### 1. Abre `.env`
```bash
nano ui/.env
# o tu editor favorito
```

### 2. Encuentra esta línea
```bash
CODE_REVIEW_ENABLED=false
```

### 3. Cámbialo a
```bash
CODE_REVIEW_ENABLED=true
```

**Listo! ✅**

---

## Qué Ocurre Ahora

Cada vez que hagas `git commit`:

```
✅ Si tu código cumple con AGENTS.md standards:
   → Commit se ejecuta normalmente

❌ Si hay violaciones de estándares:
   → Commit es BLOQUEADO
   → Ves los errores en la terminal
   → Arreglas el código
   → Haces commit de nuevo
```

---

## Ejemplo

```bash
$ git commit -m "feat: add new component"

🏁 Prowler UI - Pre-Commit Hook

ℹ️  Code Review Status: true

🔍 Running Claude Code standards validation...

📋 Files to validate:
  - components/my-feature.tsx

📤 Sending to Claude Code for validation...

STATUS: FAILED
- File: components/my-feature.tsx:45
  Rule: React Imports
  Issue: Using 'import * as React'
  Expected: import { useState } from "react"

❌ VALIDATION FAILED
Fix violations before committing

# Arreglas el archivo y haces commit de nuevo
$ git commit -m "feat: add new component"

🏁 Prowler UI - Pre-Commit Hook

ℹ️  Code Review Status: true

🔍 Running Claude Code standards validation...

✅ VALIDATION PASSED

# Commit exitoso ✅
```

---

## Desactivar Temporalmente

Si necesitas hacer commit sin validación:

```bash
# Opción 1: Cambiar en .env
CODE_REVIEW_ENABLED=false

# Opción 2: Bypass (con cuidado!)
git commit --no-verify
```

---

## Qué Valida

- ✅ React imports correctos
- ✅ TypeScript patterns (const-based types)
- ✅ Tailwind CSS (sin var() ni hex en className)
- ✅ cn() utility (solo para condicionales)
- ✅ No useMemo/useCallback sin razón
- ✅ Zod v4 syntax
- ✅ Organización de archivos
- ✅ Directivas "use client"/"use server"

---

## Más Info

Lee `CODE_REVIEW_SETUP.md` para:
- Solución de problemas
- Detalles completos
- Configuración avanzada
