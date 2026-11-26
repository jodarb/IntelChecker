# Pendientes

Puntos detectados en el repaso de la sesión de actores / empresas / cabecera que conviene plantear con calma. Están ordenados por prioridad dentro de cada bloque.

## Verificación

- [ ] **Revisión visual en navegador.** Los cambios de la vista de actor (ficha, columna lateral, pestañas fijas, leak sites), la cabecera (aviso de contraseña por defecto, botón Búsqueda), la píldora de frecuencia y el informe de empresa se han comprobado con TypeScript, ESLint y pruebas del agregador, pero no visualmente. Revisar escritorio, modo claro / oscuro y anchura de móvil.
- [ ] **Tests automáticos del frontend.** `actorProfile.ts`, `actorActivity.ts` y `relevantPulses` solo se han probado con scripts sueltos (Node ≥ 23 ejecuta TS directamente). Convertir esos casos en tests: entrada #10 (The Gentlemen), persona de RF "Gentleman", desacuerdo entre fuentes, sin perfil, una sola fuente y despliegue sin Recorded Future.
- [ ] **Tests de `/actor/resolve`.** Fijar casos (`Gentleman`, `fancy bear`, `akria`, `Play`, `scattered`, `lockbit`) para que los cambios de puntuación o agrupación no empeoren los candidatos.
- [ ] **OpenCTI contra una instancia real.** `ACTOR_CONTEXT` (300 relaciones, `x_mitre_id`, `observable_value`, `pattern`) valida contra el esquema 6.0 y master, pero no se ha probado con datos reales ni se ha medido el tamaño de la respuesta.

## Calidad de código

- [ ] **ESLint no pasa en todo `src`.** Hay 54 errores que ya existían antes de esta sesión: `no-explicit-any` en `verdictEngine.ts` y `summaryRegistry.ts`, y `react-refresh/only-export-components` en `EnginesContext.tsx` y `components/ui/button.tsx`. Decidir si se tipan o se relaja la regla en esos ficheros.
- [ ] **`HistoryDetailPage`.** `archivedAt` se crea en cada render y fuerza a recalcular la actividad del actor. Memorizarlo sin romper el orden de hooks (hoy está después de los `return` tempranos).
- [ ] **`ScoreBadge` / `WeightBadge` ocultos por contexto (`HideScores`).** Funciona para empresas. Si se recuperan las puntuaciones, quitar el contexto en lugar de dejarlo a `false`.

## Actores

- [ ] **Heurísticas de identidad.**
  - La agrupación por alias en común (claves de 3 o más caracteres) podría unir actores distintos que comparten un alias genérico.
  - La detección de "persona" depende de las categorías de Recorded Future.
  - Probar con más casos: APT28/APT29, subgrupos de Lazarus, nombres comunes como "Play" o "Medusa".
- [ ] **Arsenal atribuido frente a mencionado.** La regla actual es: atribuido si una fuente dice que lo usa, si lleva su nombre o si lo dan varias fuentes; mencionado si lo nombra una sola fuente por coocurrencia. Revisarla con más actores.
- [ ] **ransomware.live.**
  - Solo permite descargar `victims.json` y `groups.json` una vez cada 30 min por IP. Tras reiniciar el backend, la fuente da `RateLimitExceeded` (transitorio) hasta 30 min. Valorar guardar la caché en `backend/data/` para que sobreviva a los reinicios.
  - "LockBit 3.0" (clave `lockbit30`) no casa con `lockbit3`.
  - El grupo se busca solo por el nombre consultado, no por los alias que dan otras fuentes.
- [ ] **Coste de `/actor/resolve`.** Hace hasta 6 llamadas externas por búsqueda (Recorded Future y Malpedia, cada una con hasta 3 términos). Valorar una caché breve y vigilar la cuota de RF.
- [ ] **OTX para actores.**
  - La búsqueda de pulses es de texto libre y devuelve 10 resultados por relevancia, no por fecha, así que los "informes en 90 días" pueden quedarse cortos.
  - Para "Gentleman" dio timeout.
  - Valorar el endpoint de adversarios de OTX, si lo hay, o paginar.
- [ ] **Actividad.**
  - El Threat Map de Recorded Future da 403 en este despliegue (falta privilegio), así que no aporta informes.
  - La lista del historial no muestra la actividad de los actores, solo su Knowledge. Valorar guardar el nivel de actividad al guardar la entrada.
- [ ] **Modal "Cómo se calcula" en actores.** Sigue explicando también el Risk, que en actores no se muestra.
- [ ] **Historial antiguo.** Las entradas anteriores a estos cambios no tienen leak sites, `exact` de Malpedia ni `persona` de RF. Se muestran con valores por defecto: pestaña vacía y la coincidencia exacta deducida de los alias.
- [ ] **Títulos de leak sites.** Son texto controlado por el atacante. React los escapa, pero valorar ocultarlos o truncarlos más.

## Empresas

- [ ] **Puntuaciones ocultas "de momento".** El veredicto se sigue calculando, guardando en el historial y devolviendo en `POST /lookup` (con `quadrant` y `score`). Decidir si se recupera la vista, se rediseña o se deja de calcular.
- [ ] **Peso de Recorded Future en empresas.** Usa el Knowledge general de RF (9), que es alto para una fuente que solo da contexto. Valorar un `knowledge_by_type.company` propio.
- [ ] **Desambiguación en Recorded Future.** `entity-match` elige por nombre y alias; no se puede filtrar por dominio. "Iberia" encuentra la aerolínea, pero otros nombres ambiguos pueden fallar. El endpoint de riesgo de terceros (`/v2/company`) necesita un permiso que la clave actual no tiene.

## Interfaz

- [ ] **Cabecera en pantallas estrechas.** Los botones del menú y el aviso de contraseña por defecto (`whitespace-nowrap`) pueden desbordar en móvil.
- [ ] **Botón "Volver".** Se quitó del detalle del historial, pero sigue en los resultados en vivo ("← Volver"). Decidir un criterio común.
- [ ] **Botón "Búsqueda".** Siempre lleva a Artefactos. Valorar recordar la última pestaña usada (Artefactos, Actores o Empresas).
- [ ] **`docs/screenshot.png`.** Está desactualizada: faltan las pestañas Actores / Empresas y la nueva vista de actor.
