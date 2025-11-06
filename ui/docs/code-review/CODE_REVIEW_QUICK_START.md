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

Cada vez que hagas `git push`:

```
✅ Si tu código cumple con AGENTS.md standards:
   → Push se ejecuta normalmente

❌ Si hay violaciones de estándares:
   → Push es BLOQUEADO
   → Ves los errores en la terminal
   → Arreglas el código
   → Haces push de nuevo
```

---

## Ejemplo

```bash
$ git push

🔍 Running Claude Code standards validation...

📋 Files being pushed:
  - components/my-feature.tsx

📤 Sending to Claude Code...

STATUS: FAILED
- File: components/my-feature.tsx:45
  Rule: React Imports
  Issue: Using 'import * as React'
  Expected: import { useState } from "react"

❌ VALIDATION FAILED
Please fix the violations...

# Arreglas el archivo y haces push de nuevo
$ git push
✅ VALIDATION PASSED
✅ Build completed
✅ Pre-push checks completed!
# Push exitoso ✅
```

---

## Desactivar Temporalmente

Si necesitas pushear sin validación:

```bash
# Opción 1: Cambiar en .env
CODE_REVIEW_ENABLED=false

# Opción 2: Bypass (con cuidado!)
git push --no-verify
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
