# Pendientes

Lo que queda por hacer o decidir, ordenado por prioridad dentro de cada bloque. Al final, lo ya hecho en esta tanda.

Última actualización: 2026-11-27 (todo subido a `main` y desplegado en Docker).

## Calidad de código

- [ ] **`eslint-disable` de `no-explicit-any` en otros ficheros.** ESLint ya pasa en todo el proyecto, pero cinco ficheros siguen silenciando `any` en bloque: `actorProfile.ts`, `actorActivity.ts`, `intelAggregates.ts`, `components/company/CompanyReport.tsx` y `scripts/verdict-cli.ts`. Tiparlos con el mismo método que `verdictEngine.ts` (interfaces mínimas por fuente, sin cambiar la lógica) si se quiere el proyecto sin excepciones.

## Verificación con datos reales

- [ ] **OpenCTI contra una instancia real.** `ACTOR_CONTEXT` (300 relaciones, `x_mitre_id`, `observable_value`, `pattern`) valida contra el esquema 6.0 y master, pero no se ha probado con datos reales ni se ha medido el tamaño de la respuesta. Comprobar también el país de origen (`originates-from` → `Country`).
- [ ] **Caché de ransomware.live con el servicio real.** La persistencia en `backend/data/feeds/` está probada sin red; la lista Tor ya se guarda y se restaura en Docker (`tor-exit-nodes.gz`), pero las de ransomware.live todavía no existen: se crearán con la primera consulta de actor o empresa que use esa fuente. Comprobar entonces que aparecen y que un reinicio no da `RateLimitExceeded`.

## Actores

- [ ] **Heurísticas de identidad.**
  - La agrupación por alias en común (claves de 3 o más caracteres) podría unir actores distintos que comparten un alias genérico.
  - La detección de "persona" depende de las categorías de Recorded Future.
  - Probar con más casos: APT28/APT29, subgrupos de Lazarus, nombres comunes como "Play" o "Medusa".
- [ ] **País de origen desde la descripción de MITRE.** Es heurístico (dos primeras frases, patrones como "China-based" o "attributed to Russia's…"). Revisarlo con más grupos y vigilar falsos positivos.
- [ ] **Arsenal atribuido frente a mencionado.** Atribuido si una fuente dice que lo usa, si lleva su nombre o si lo dan varias fuentes; mencionado si lo nombra una sola fuente por coocurrencia. Revisar la regla con más actores.
- [ ] **OTX para actores.**
  - La búsqueda de pulses es de texto libre y devuelve 10 resultados por relevancia, no por fecha, así que los "informes en 90 días" pueden quedarse cortos.
  - Para "Gentleman" dio timeout.
  - Valorar el endpoint de adversarios de OTX, si lo hay, o paginar.
- [ ] **Actividad.**
  - El Threat Map de Recorded Future da 403 en este despliegue (falta privilegio), así que no aporta informes.
  - La lista del historial no muestra la actividad de los actores, solo su Knowledge. Valorar guardar el nivel de actividad al guardar la entrada.
- [ ] **Historial antiguo.** Las entradas anteriores a estos cambios no tienen leak sites, `exact` de Malpedia ni `persona` de RF. Se muestran con valores por defecto: pestaña vacía y la coincidencia exacta deducida de los alias.
- [ ] **Títulos de leak sites.** Son texto controlado por el atacante. React los escapa, pero valorar ocultarlos o truncarlos más.

## Empresas

- [ ] **Desambiguación en Recorded Future.** `entity-match` elige por nombre y alias; no se puede filtrar por dominio. "Iberia" encuentra la aerolínea, pero otros nombres ambiguos pueden fallar. El endpoint de riesgo de terceros (`/v2/company`) necesita un permiso que la clave actual no tiene.

---

## Hecho (2026-11-27)

**Decisiones aplicadas**
- [x] **Las empresas no se puntúan** (`2f8f3c8`). `computeVerdict` / `compute_verdict` devuelven un veredicto vacío para `company` (sin Risk, Knowledge ni cuadrante); `POST /history` guarda nulos, `POST /lookup` los devuelve (y `outcome` / `subscore` / `depth` nulos por fuente); las entradas antiguas conservan su puntuación en la base de datos pero la API ya no la devuelve. Admin no muestra las fuentes solo de empresa (Wikidata, GLEIF, Hudson Rock, Have I Been Pwned, GDELT) ni el ajuste por tipo "Empresa". Quitadas las etiquetas `quadrant.company.*`. La valoración interna por fuente solo ordena las tarjetas del informe. Con esto deja de tener sentido el peso de Recorded Future en empresas, que estaba pendiente.
- [x] **Botón "Volver" unificado** (`2f8f3c8`, `components/BackButton.tsx`): en todas las vistas salvo las tres de búsqueda y el inicio de sesión, siempre primero, a la izquierda del título, con el texto "Volver". Vuelve a la pantalla anterior de la app; si la página se abrió directamente, a su vista padre.
- [x] **"Búsqueda" siempre lleva a Artefactos**: no recuerda la última pestaña (decidido; ya era así).

**Funcionalidades**
- [x] **Relanzar desde el historial** (`d655752`). Botón ↻ en cada fila y "Relanzar" en el detalle (`lib/rerun.ts`): artefactos con el mismo tipo, actores con el nombre guardado, empresas con `Nombre (dominio, Q-id, LEI)`. Solo con permiso `analyze`.
- [x] **País de origen del actor** (`d655752`). `lib/countries.ts` normaliza a ISO (códigos, nombres oficiales, nombres en español, gentilicios); `profile.origins` cuenta cuántas fuentes dan cada país. Insignia "Origen" (+N si no coinciden) y bloque "País de origen" en el lateral. Fuentes: MITRE (descripción), Malpedia (país y patrocinador), RF ("<país> Nation State Sponsored"), OpenCTI (`originates-from`, que ya no se cuenta como país atacado).
- [x] **Lista del historial** (`aba56c3`). Marca de tiempo, artefacto (icono, indicador, tipo) y usuario con icono; puntuaciones a la derecha. En móvil la hora va en su propia línea; las IPs ya no se recortan.

**Fuentes y backend**
- [x] **ransomware.live por alias.** Si ningún grupo tiene el nombre buscado, prueba los alias de MITRE ATT&CK del actor (ya en memoria, sin llamadas extra): "GOLD SAHARA" → `akira`. La tarjeta dice con qué alias se encontró y la identidad no cuenta como coincidencia exacta. Los alias que solo da Malpedia (p. ej. "Storm-1567") no se prueban, porque harían falta llamadas externas.
- [x] **Caché de `/actor/resolve`.** Las búsquedas en Malpedia y Recorded Future se guardan 15 min por término (hasta 500), con la API key de RF en la clave; los fallos no se guardan. Repetir o reformular una búsqueda ya no gasta cuota.
- [x] **Caché persistente** (`d655752`, `2c0e291`). `CachedFeed(persist=…)` guarda la última descarga buena en `backend/data/feeds/` (gzip): ransomware.live (víctimas y grupos) y Tor Exit Nodes (dan.me.uk, que responde 403 al pasar el límite: `rate_limit_status`). Al reiniciar se parte de la copia; si caducó y la descarga falla, se sirve la antigua.
- [x] **"LockBit 3.0"** casa con `lockbit3` (`0da5beb`).

**Interfaz**
- [x] **Admin en móvil**: cada fuente apilada (nombre, Risk, Knowledge con su etiqueta, ajuste por tipo); desde `sm`, la tabla de siempre.
- [x] **Revisión visual** con Playwright en escritorio, tablet y móvil, modo claro y oscuro (`0da5beb`, `d655752`).
- [x] **Cabecera y menú**: se reparte en varias líneas; iconos entre `md` y `xl`; desplegable en móvil; pestañas con scroll.
- [x] **`<button>` dentro de `<button>`**: las 20 cabeceras de tarjeta son `div role="button"` con teclado (`lib/a11y.ts`).
- [x] **Contraste en modo claro** de píldoras, insignias y actividad.
- [x] **Ficha del actor**: cifras en filas equilibradas, chips largos recortados, plural "1 fuente", modal "Cómo se calcula" solo con Knowledge.
- [x] **`docs/screenshot.png`** con el informe de actor.

**Calidad**
- [x] **ESLint en verde en todo el proyecto** (antes 54 errores). `verdictEngine.ts`: cada fuente se lee con una interfaz mínima de los campos que usa (sin cambiar la lógica: paridad 0 diferencias, también con el historial real) y sin bloques `eslint-disable`; `summaryRegistry.ts`: helpers `at()` / `val()` y test de los extractores; el contexto de motores y `useEngines()` pasan a `hooks/useEngines.ts`; `buttonVariants` deja de exportarse.
- [x] **Tests**: frontend `npm test` (54, con los extractores del resumen; antes 47: perfil, actividad, `relevantPulses`, países, empresas sin puntuación, ransomware.live por alias); backend `actor_resolve_check.py` (13, con la caché), `feeds_persist_check.py` (10), `company_unscored_check.py` (3) y `ransomwarelive_actor_check.py` (5); paridad del veredicto sin diferencias.
- [x] **`archivedAt`** memorizado en `HistoryDetailPage`.
