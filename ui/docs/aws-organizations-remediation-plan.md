# AWS Organizations Wizard Remediation Plan

## Objetivo
Corregir bugs funcionales y deuda técnica detectada en la rama del nuevo wizard de proveedores, manteniendo la UX acordada para AWS Organizations.

## Decisiones Confirmadas
- El backend **no garantiza** el orden de `relationships.providers.data` respecto a `accounts` en `applyDiscovery`.
- Debemos **mantener** la validación de conexiones al pulsar `Test Connections`.
- Debemos **actualizar E2E** al flujo modal actual y eliminar dependencia de rutas legacy.

## Alcance
- UI (`ui/components/providers/**`, `ui/actions/**`, `ui/store/**`, `ui/types/**`).
- Tests E2E (`ui/tests/providers/**`).
- Documentación técnica en `ui/docs/**`.
- Si hace falta contrato backend para mapping determinista, incluir cambio en API dentro del mismo PR o PR dependiente explícito.

## Plan de Ejecución

## Fase 1: Corregir Bugs Críticos de Datos
### 1.1 Mapping determinista Account -> Provider
- Problema actual: se hace mapping por índice entre `sanitizedSelectedAccountIds` y `providers.data`.
- Riesgo: errores y estados de conexión asignados a cuentas equivocadas.
- Acción:
  - Introducir mapping explícito en la respuesta de `applyDiscovery` (preferido): `[{ account_id, provider_id }]`.
  - Adaptar frontend para construir `accountToProviderMap` con ese mapping, sin usar índices.
  - Fallback temporal solo si el backend no llega: resolver providers por `uid === accountId` en una consulta controlada.
- Criterio de aceptación:
  - Con response desordenada, cada cuenta sigue mostrando su propio estado/error correctamente.

## Fase 2: Normalizar Polling y Reducir Agresividad
### 2.1 Test Connections polling
- Acción:
  - Limitar concurrencia de tests (ejemplo: 5 en paralelo).
  - Aumentar intervalo base o usar backoff (ejemplo: 2s -> 3s -> 5s, con tope).
  - Eliminar `getTask` extra final si `checkTaskStatus` ya devuelve `result` completo.
- Criterio de aceptación:
  - Menos requests por minuto sin empeorar tiempo total percibido.
  - No hay picos masivos al testear organizaciones grandes.

### 2.2 Discovery polling duplicado
- Acción:
  - Mantener **un solo owner** de polling para discovery.
  - Eliminar o integrar `OrgDiscoveryLoader` si sigue siendo ruta muerta.
  - Conservar la pantalla de `Validate Connection` para test de cuentas, que sí es obligatoria.
- Criterio de aceptación:
  - No existe doble polling para discovery en el flujo real.

## Fase 3: Limpieza de Código Stale/No Usado
### 3.1 Limpieza funcional
- Eliminar bloques de UI inalcanzables (ejemplo: `DETAILS && isSubmitting` en setup).
- Eliminar props no usadas o cablearlas correctamente (ejemplo: `hasConnectionErrors` en stepper).
- Revisar y eliminar lógica redundante de estados intermedios de wizard.

### 3.2 Limpieza documental
- Actualizar `ui/docs/aws-organizations-bulk-connect.md` para reflejar flujo modal.
- Marcar explícitamente como legacy cualquier sección basada en rutas eliminadas.

## Fase 4: Actualizar E2E al Flujo Modal
### 4.1 Refactor de page object
- Sustituir asunciones de URL legacy (`/providers/connect-account`, `/add-credentials`, `/test-connection`, `/update-credentials`) por selectores del modal y estados del stepper.
- Añadir helpers para:
  - abrir/cerrar modal,
  - avanzar por pasos del wizard,
  - validar transiciones internas por contenido visible, no por URL.

### 4.2 Cobertura mínima recomendada
- Alta de provider single-account.
- Alta por Organizations + `Test Connections`.
- Retry parcial cuando fallan algunas cuentas.
- Back navigation desde account tree hacia `Authentication Details`.
- Launch scan con selector `daily/single`.

## Fase 5: Validación y Hardening
- Ejecutar `typecheck`, `eslint`, tests unitarios y E2E afectados.
- Añadir test unitario del mapping account->provider sin orden estable.
- Añadir test unitario del controlador de polling (concurrencia/backoff).
- Checklist final:
  - Sin logs de debug residuales.
  - Sin imports/props dead.
  - Sin documentos desalineados con la implementación.

## Entregables
- Código corregido en UI (y API si se requiere contrato de mapping).
- E2E migrados y verdes.
- Documentación actualizada.
- Nota de PR con riesgos, decisiones y estrategia de rollback.

## Riesgos y Mitigación
- Dependencia de contrato backend para mapping: mitigar con fallback temporal documentado.
- Cambios en E2E pueden romper suites existentes: migrar page object en un PR dedicado y reusar helpers.
- Ajustar polling puede alterar timing de UX: validar con organizaciones pequeñas y grandes.

## Orden Recomendado de PRs
1. PR de bug crítico de mapping account->provider.
2. PR de polling/concurrencia.
3. PR de limpieza stale + docs.
4. PR de migración E2E.
