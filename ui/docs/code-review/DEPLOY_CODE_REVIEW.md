# Deploy Code Review System

Instrucciones para configurar el sistema de Code Review en Prowler UI.

## Resumen

Se ha implementado un sistema de validación automática que:

- ✅ Valida código contra estándares AGENTS.md antes de pushear
- ✅ Usa Claude Code (que ya está en tu PATH)
- ✅ Solo valida archivos que van a ser pusheados
- ✅ Se puede activar/desactivar fácilmente con una variable de entorno
- ✅ Bloquea push si hay violaciones (exit code 1)

## Cambios Realizados

### 1. Archivo: `ui/.env`

Agregado bloque de configuración:

```bash
#### Code Review Configuration ####
# Enable Claude Code standards validation on pre-push hook
# Set to 'true' to validate changes against AGENTS.md standards via Claude Code
# Set to 'false' to skip validation
CODE_REVIEW_ENABLED=false
```

**Por qué `false` por defecto:**
- No interrumpe el flujo de trabajo actual
- Developers pueden habilitar cuando lo deseen
- Evita bloqueos inesperados

### 2. Archivo: `ui/.husky/pre-push`

Completamente reescrito con lógica de validación:

```bash
#!/bin/bash
# Lee .env
# Si CODE_REVIEW_ENABLED=true:
#   - Obtiene archivos que van a ser pusheados
#   - Construye prompt con contenido de archivos
#   - Envía a `claude-code` CLI
#   - Parsea respuesta buscando "STATUS: PASSED" o "STATUS: FAILED"
#   - Si FAILED → exit 1 (bloquea push)
#   - Si PASSED → continúa
# Ejecuta npm run build (siempre)
```

### 3. Documentación: `CODE_REVIEW_QUICK_START.md`

Guía rápida para developers:
- 3 pasos para activar
- Ejemplos de uso
- Cómo desactivar si es necesario

### 4. Documentación: `CODE_REVIEW_SETUP.md`

Guía completa:
- Instalación detallada
- Cómo funciona el flujo
- Qué valida exactamente
- Solución de problemas
- Configuración avanzada

### 5. Documentación: `CODE_REVIEW_TESTING.md`

Guía de testing:
- Cómo probar cada componente
- Test cases reales
- Troubleshooting

## Instalación

### Para Usuarios Finales (Developers)

1. **Abre `ui/.env`**

2. **Busca esta línea** (alrededor de línea 174):
   ```bash
   CODE_REVIEW_ENABLED=false
   ```

3. **Cámbialo a:**
   ```bash
   CODE_REVIEW_ENABLED=true
   ```

4. **Guarda el archivo**

5. **Próximo push validará automáticamente:**
   ```bash
   git push

   # Si CODE_REVIEW_ENABLED=true, verás:
   🔍 Running Claude Code standards validation...
   ```

### Para Lead/Maintainers

**No hay setup adicional necesario.** El sistema está listo para usar.

Lo único a verificar:
```bash
# El hook debe ser executable
ls -la .husky/pre-push
# Debe mostrar: -rwxr-xr-x

# Si no, ejecuta:
chmod +x .husky/pre-push
```

## Cómo Funciona

### Flujo Standard (Desactivado - Default)

```
git push
  ↓
Hook pre-push se ejecuta
  ↓
CODE_REVIEW_ENABLED=false
  ↓
Salta validación
  ↓
npm run build
  ↓
Push ✅
```

### Flujo con Validación (Activado)

```
git push
  ↓
Hook pre-push se ejecuta
  ↓
CODE_REVIEW_ENABLED=true
  ↓
Obtiene archivos a pushear
  ↓
Construye prompt con código
  ↓
claude-code < prompt.txt
  ↓
Claude analiza código
  ↓
Retorna: STATUS: PASSED o STATUS: FAILED
  ↓
Si PASSED:
  npm run build
  Push ✅

Si FAILED:
  Muestra violaciones
  exit 1
  Push ❌
```

## Qué Valida

El sistema está configurado para detectar violaciones de:

1. **React Imports**
   - ❌ `import * as React`
   - ✅ `import { useState }`

2. **TypeScript Type Patterns**
   - ❌ `type Status = "a" | "b"`
   - ✅ `const STATUS = {...} as const`

3. **Tailwind CSS**
   - ❌ `className="bg-[var(...)]"`
   - ✅ `className="bg-card-bg"`

4. **cn() Utility**
   - ❌ `className={cn("static")}`
   - ✅ `className={cn("h-3", isActive && "bg-blue")}`

5. **React 19 Hooks**
   - ❌ `useMemo()` sin razón
   - ✅ Sin useMemo (React Compiler)

6. **Zod v4 Syntax**
   - ❌ `z.string().email()`
   - ✅ `z.email()`

7. **File Organization**
   - ❌ Código compartido en carpeta feature-specific
   - ✅ Siguiendo The Scope Rule

8. **Directives**
   - ❌ Server Action sin `"use server"`
   - ✅ Directivas correctas

## Exit Codes (Para CI/CD)

El script pre-push retorna:

```bash
exit 0  # ✅ Push permitido (validación pasó o desactivada)
exit 1  # ❌ Push bloqueado (validación falló)
```

Esto permite que se use en:
- GitHub Actions
- GitLab CI
- Otros sistemas de CI/CD

## Desactivar Temporalmente

```bash
# Opción 1: Cambiar en .env
CODE_REVIEW_ENABLED=false

# Opción 2: Bypass (salta todos los hooks)
git push --no-verify

# Opción 3: Desactivar el hook temporalmente
chmod -x .husky/pre-push
git push
chmod +x .husky/pre-push
```

## Troubleshooting

### "claude-code: command not found"

```bash
# Verifica dónde está Claude Code
which claude-code

# Si no aparece, agrega a ~/.zshrc:
export PATH="$HOME/.local/bin:$PATH"

# Recarga:
source ~/.zshrc
```

### Hook no se ejecuta

```bash
# Verifica que sea ejecutable
ls -la .husky/pre-push

# Debe mostrar: -rwxr-xr-x
# Si no, ejecuta:
chmod +x .husky/pre-push
```

### Validación inconclusa

Si el análisis de Claude no retorna status claro:
- Se permite el push automáticamente
- Se muestra advertencia en la terminal
- Developer puede revisar manualmente

## Para El Equipo

**Recomendación:**

1. **Durante desarrollo:** `CODE_REVIEW_ENABLED=false`
   - Iteras rápido
   - Build check aún se ejecuta

2. **Antes de PR final:** `CODE_REVIEW_ENABLED=true`
   - Valida que cumplas estándares
   - Previene PRs rechazadas

3. **En CI/CD (futuro):** Agregar validación server-side
   ```bash
   # GitHub Actions podría ejecutar:
   npm run code-review:ci
   ```

## Documentación Disponible

Después de esta implementación, hay 4 documentos:

1. **CODE_REVIEW_QUICK_START.md** ← Leer primero
2. **CODE_REVIEW_SETUP.md** ← Para detalles
3. **CODE_REVIEW_TESTING.md** ← Para testing
4. **DEPLOY_CODE_REVIEW.md** ← Este documento

## Próximos Pasos

### Corto Plazo
- [ ] Revisar archivos generados
- [ ] Testear con `CODE_REVIEW_ENABLED=true`
- [ ] Compartir documentación con equipo

### Mediano Plazo
- [ ] Recolectar feedback de developers
- [ ] Ajustar reglas de validación si es necesario
- [ ] Considerar automatizar más casos

### Largo Plazo
- [ ] Agregar validación en CI/CD
- [ ] Integrar con GitHub/GitLab para comentarios automáticos
- [ ] Expandir suite de validación

## Resumen Técnico

```
┌─────────────────────────────────────────────────────┐
│  .env                                               │
│  CODE_REVIEW_ENABLED=true/false                     │
└────────────────────┬────────────────────────────────┘
                     │
                     ↓
        ┌────────────────────────────────┐
        │  .husky/pre-push (bash script)  │
        │                                │
        │  1. Leer CONFIG_REVIEW_ENABLED  │
        │  2. Si true:                    │
        │     - git diff origin...HEAD    │
        │     - cat archivos             │
        │     - claude-code < prompt     │
        │     - grep STATUS              │
        │     - exit 0/1                 │
        │  3. npm run build              │
        │  4. exit                       │
        └────────────────────────────────┘
                     │
                     ↓
          ┌──────────────────────┐
          │  Shell Exit Code     │
          │  0 = Push OK ✅      │
          │  1 = Push Blocked ❌ │
          └──────────────────────┘
```

## Soporte

Si hay preguntas:
1. Lee CODE_REVIEW_QUICK_START.md (comienza aquí)
2. Lee CODE_REVIEW_SETUP.md (detalles técnicos)
3. Lee CODE_REVIEW_TESTING.md (testing)
4. Revisa AGENTS.md (estándares que valida)

---

**Status:** ✅ Implementación completa y lista para usar.

Activar cuando el equipo esté listo.
