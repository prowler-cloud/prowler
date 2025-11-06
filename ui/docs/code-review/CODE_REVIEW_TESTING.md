# Code Review - Testing Guide

Guía para probar que la validación funciona correctamente.

## Test 1: Validación Desactivada (Default)

### Configuración
```bash
# En .env
CODE_REVIEW_ENABLED=false
```

### Resultado Esperado
```bash
$ git push

🚀 Prowler UI - Pre-Push Hook
ℹ️  Code Review Status: false

⏭️  Code review disabled (CODE_REVIEW_ENABLED=false)
To enable: set CODE_REVIEW_ENABLED=true in .env

📋 Files being pushed (not validated):
  - (lista de archivos)

🔨 Building project...
# Build se ejecuta

✅ Pre-push checks completed successfully!
# Push continúa ✅
```

**✅ Prueba pasó:** La validación se salta cuando está desactivada.

---

## Test 2: Activar Validación

### Configuración
```bash
# En .env
CODE_REVIEW_ENABLED=true
```

### Crear archivo de prueba con violación

```bash
# Crea un archivo temporal con un error
cat > /tmp/test-violation.tsx << 'EOF'
import * as React from "react";  // ❌ Violación: React import incorrecto
import { useState } from "react";

export function MyComponent() {
  const [count, setCount] = useState(0);
  return <div>{count}</div>;
}
EOF

# Copia al proyecto
cp /tmp/test-violation.tsx ui/components/test-violation.tsx
git add ui/components/test-violation.tsx
git commit -m "test: violation for testing"
```

### Resultado Esperado
```bash
$ git push

🚀 Prowler UI - Pre-Push Hook
ℹ️  Code Review Status: true

🔍 Running Claude Code standards validation...

📋 Files being pushed:
  - components/test-violation.tsx

📤 Sending to Claude Code...

=== VALIDATION REPORT ===
STATUS: FAILED

- File: components/test-violation.tsx:1
  Rule: React Imports
  Issue: Using 'import * as React from "react"' - should use named imports only
  Expected: import { useState } from "react"

❌ VALIDATION FAILED

Please fix the violations before pushing:
  1. Review the violations listed above
  2. Fix the code according to AGENTS.md standards
  3. Commit your changes
  4. Try pushing again
```

**✅ Prueba pasó:** La validación detecta violaciones y bloquea el push.

---

## Test 3: Corregir Violación

### Arreglar el archivo
```bash
# Edita el archivo
cat > ui/components/test-violation.tsx << 'EOF'
import { useState } from "react";  // ✅ Correcto

export function MyComponent() {
  const [count, setCount] = useState(0);
  return <div>{count}</div>;
}
EOF

git add ui/components/test-violation.tsx
git commit -m "fix: correct React imports"
```

### Resultado Esperado
```bash
$ git push

🔍 Running Claude Code standards validation...

📋 Files being pushed:
  - components/test-violation.tsx

📤 Sending to Claude Code...

=== VALIDATION REPORT ===
STATUS: PASSED
All files comply with AGENTS.md standards.

✅ VALIDATION PASSED

🔨 Building project...
npm run build...

✅ Pre-push checks completed successfully!
# Push continúa ✅
```

**✅ Prueba pasó:** Después de arreglar, el push se ejecuta normalmente.

---

## Test 4: Limpiar

```bash
# Remueve el archivo de prueba
git rm ui/components/test-violation.tsx
git commit -m "test: remove test-violation file"
git push
```

---

## Test 5: Validación con Bypass (Opcional)

Para verificar que el bypass funciona:

```bash
# Sin validación, fuerza el push
git push --no-verify

# ⚠️ ADVERTENCIA: Esto salta TODOS los hooks
# Incluye el build check
```

**✅ Prueba pasó:** El flag `--no-verify` permite saltar hooks cuando es necesario.

---

## Casos de Uso Reales

### Caso 1: Tailwind CSS Violation

```bash
# ❌ Incorrecto
className="bg-[var(--color-bg)]"

# ✅ Correcto
className="bg-card-bg"
```

### Caso 2: Type Pattern Violation

```bash
# ❌ Incorrecto
type Status = "active" | "inactive" | "pending"

# ✅ Correcto
const STATUS = {
  ACTIVE: "active",
  INACTIVE: "inactive",
  PENDING: "pending",
} as const
type Status = typeof STATUS[keyof typeof STATUS]
```

### Caso 3: cn() Misuse

```bash
# ❌ Incorrecto
className={cn("flex items-center")}

# ✅ Correcto
className={cn("h-3 w-3", isActive ? "bg-blue" : "bg-gray")}
```

### Caso 4: React Hook Violation

```bash
// ❌ Incorrecto
const memoized = useMemo(() => heavyComputation(), [])

// ✅ Correcto
const result = heavyComputation()  // React 19 Compiler optimiza automáticamente
```

---

## Checklist de Testing

- [ ] Test 1: Validación desactivada → push normal ✅
- [ ] Test 2: Validación activa con error → push bloqueado ✅
- [ ] Test 3: Arreglar error → push exitoso ✅
- [ ] Test 4: Limpiar archivos de prueba ✅
- [ ] Test 5: Bypass con --no-verify funciona ✅
- [ ] Claude Code disponible en PATH ✅
- [ ] Hook es ejecutable (chmod +x) ✅

---

## Troubleshooting

### Error: "claude-code: command not found"

```bash
# Verifica instalación
which claude-code

# Si no existe, agrega a PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Error: Hook no ejecuta

```bash
# Verifica que sea ejecutable
ls -la .husky/pre-push
# Debe mostrar: -rwxr-xr-x

# Si no, hazlo ejecutable
chmod +x .husky/pre-push
```

### Error: Build falla después de validación

```bash
# La validación pasó pero el build falló
# Arregla los errores del build:
npm run build

# Luego haz push de nuevo
git push
```

---

## Para CI/CD (Futuro)

Este sistema es para validación local. En el futuro podrías agregar:

```bash
# En GitHub Actions
- Run: npm run code-review:ci
# Valida todos los archivos del PR contra estándares
```
