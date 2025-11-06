# Code Review Setup - Prowler UI

Guía para configurar la validación automática de código con Claude Code en el pre-push hook.

## Descripción General

El sistema de code review funciona así:

1. **Cuando activas `CODE_REVIEW_ENABLED=true` en `.env`**
   - Al hacer `git push`, el hook pre-push se ejecuta
   - Solo valida los archivos TypeScript/JavaScript que vas a pushear
   - Usa Claude Code para analizar si cumplen con AGENTS.md
   - Si hay violaciones → **BLOQUEA el push**
   - Si todo está bien → Continúa normalmente

2. **Cuando `CODE_REVIEW_ENABLED=false` (default)**
   - El hook pre-push solo ejecuta `npm run build`
   - No hay validación de estándares
   - Los developers pueden pushear sin restricciones

## Instalación

### 1. Asegúrate que Claude Code esté en tu PATH

```bash
# Verifica que claude-code esté disponible en terminal
which claude-code

# Si no aparece, agrega a tu ~/.zshrc o ~/.bashrc:
# export PATH="$HOME/.claude/bin:$PATH"
# (o donde tengas instalado claude-code)
```

### 2. Activa la validación en `.env`

En `/ui/.env`, busca la sección "Code Review Configuration":

```bash
#### Code Review Configuration ####
# Enable Claude Code standards validation on pre-push hook
# Set to 'true' to validate changes against AGENTS.md standards via Claude Code
# Set to 'false' to skip validation
CODE_REVIEW_ENABLED=false  # ← Cambia esto a 'true'
```

**Opciones:**
- `CODE_REVIEW_ENABLED=true` → Activa validación
- `CODE_REVIEW_ENABLED=false` → Desactiva validación (default)

### 3. El hook está listo

El archivo `.husky/pre-push` ya contiene la lógica. No necesitas instalar nada más.

## Cómo Funciona

### Flujo Normal (con validación activada)

```bash
$ git push

# Hook pre-push se ejecuta automáticamente
🚀 Prowler UI - Pre-Push Hook
ℹ️  Code Review Status: true

📋 Files being pushed (to validate):
  - components/new-feature.tsx
  - types/new-feature.ts

📤 Sending to Claude Code for validation...

# Claude analiza los archivos...

=== VALIDATION REPORT ===
STATUS: PASSED
All files comply with AGENTS.md standards.

✅ VALIDATION PASSED
🔨 Building project...
npm run build...

✅ Pre-push checks completed successfully!
# Push continúa ✅
```

### Si Hay Violaciones

```bash
$ git push

# Claude detecta problemas...

=== VALIDATION REPORT ===
STATUS: FAILED

- File: components/new-feature.tsx:15
  Rule: React Imports
  Issue: Using 'import * as React' instead of named imports
  Expected: import { useState } from "react"

❌ VALIDATION FAILED

Please fix the violations before pushing:
  1. Review the violations listed above
  2. Fix the code according to AGENTS.md standards
  3. Commit your changes
  4. Try pushing again

# Push es BLOQUEADO ❌
```

## Qué Valida

El sistema verifica que los archivos cumplan con:

### 1. React Imports
```typescript
// ❌ INCORRECTO
import * as React from "react"
import React, { useState } from "react"

// ✅ CORRECTO
import { useState } from "react"
```

### 2. TypeScript Type Patterns
```typescript
// ❌ INCORRECTO
type SortOption = "high-low" | "low-high"

// ✅ CORRECTO
const SORT_OPTIONS = {
  HIGH_LOW: "high-low",
  LOW_HIGH: "low-high",
} as const
type SortOption = typeof SORT_OPTIONS[keyof typeof SORT_OPTIONS]
```

### 3. Tailwind CSS
```typescript
// ❌ INCORRECTO
className="bg-[var(--color)]"
className="text-[#ffffff]"

// ✅ CORRECTO
className="bg-card-bg text-white"
```

### 4. cn() Utility
```typescript
// ❌ INCORRECTO
className={cn("flex items-center")}

// ✅ CORRECTO
className={cn("h-3 w-3", isCircle ? "rounded-full" : "rounded-sm")}
```

### 5. React 19 Hooks
```typescript
// ❌ INCORRECTO
const memoized = useMemo(() => value, [])

// ✅ CORRECTO
// No usar useMemo (React Compiler lo maneja)
const value = expensiveCalculation()
```

### 6. Zod v4 Syntax
```typescript
// ❌ INCORRECTO
z.string().email()
z.string().nonempty()

// ✅ CORRECTO
z.email()
z.string().min(1)
```

### 7. File Organization
```
// ❌ INCORRECTO
Código usado por 2+ features en carpeta feature-specific

// ✅ CORRECTO
Código usado por 1 feature → local en esa feature
Código usado por 2+ features → en shared/global
```

### 8. Use Directives
```typescript
// ❌ INCORRECTO
export async function updateUser() { } // Falta "use server"

// ✅ CORRECTO
"use server"
export async function updateUser() { }
```

## Desactivar Temporalmente

Si necesitas hacer push sin validación temporalmente:

```bash
# Opción 1: Cambiar en .env
CODE_REVIEW_ENABLED=false
git push

# Opción 2: Usar git hook bypass
git push --no-verify

# Opción 3: Desactivar el hook
chmod -x .husky/pre-push
git push
chmod +x .husky/pre-push
```

**⚠️ Nota:** `--no-verify` salta TODOS los hooks, incluyendo el build check.

## Solución de Problemas

### "Claude Code CLI not found"

```
⚠️ Claude Code CLI not found in PATH
To enable: ensure Claude Code is in PATH and CODE_REVIEW_ENABLED=true
```

**Solución:**
```bash
# Verifica dónde está instalado claude-code
which claude-code

# Si no aparece, agrega a tu ~/.zshrc:
export PATH="$HOME/.local/bin:$PATH"  # o donde esté instalado

# Recarga la terminal
source ~/.zshrc
```

### "Validation inconclusive"

Si Claude Code no puede determinar el status:

```
⚠️ Could not determine validation status
Allowing push (validation inconclusive)
```

El push se permite automáticamente. Si quieres ser más estricto, puedes:

1. Revisar manualmente los archivos contra AGENTS.md
2. Reportar el problema del análisis a Claude

### Build falla después de validación

```
❌ Build failed
```

Si la validación pasa pero el build falla:

1. Revisa el error del build
2. Arréglalo localmente
3. Haz commit y push de nuevo

## Ver el Reporte Completo

Los reportes se guardan en archivos temporales que se eliminan después. Para ver el reporte detallado en tiempo real, observa la salida del hook:

```bash
git push 2>&1 | tee push-report.txt
```

Esto guardará todo en `push-report.txt`.

## Para el Equipo

### Activar en tu máquina

```bash
cd ui
CODE_REVIEW_ENABLED=true
# Edita .env localmente
```

### Flujo Recomendado

1. **Durante desarrollo**: `CODE_REVIEW_ENABLED=false`
   - Iteras más rápido
   - El build check aún se ejecuta

2. **Antes de push final**: `CODE_REVIEW_ENABLED=true`
   - Valida que cumplas con estándares
   - Previene PRs rechazadas por violaciones

3. **En CI/CD**: Podrías agregar una validación adicional
   - (futuro) Validación server-side en GitHub Actions

## Contacto

Si tienes preguntas sobre los estándares validados, revisa:
- `AGENTS.md` - Guía completa de arquitectura
- `CLAUDE.md` - Instrucciones específicas del proyecto
