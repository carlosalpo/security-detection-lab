# Captions e índice / Captions and index

Todas las imágenes son capturas reales del navegador de un **visor de evidencia**, creado a partir de salidas locales retenidas. **No es UI del producto ni una captura de Terminal.** Eventos sintéticos, replay offline; sin SIEM, ataques, tráfico ni escaneos.

All images are actual browser screenshots of an **evidence viewer** built from retained local outputs. **Not product UI or a Terminal screenshot.** Synthetic events, offline replay; no SIEM connection, attacks, traffic or scanning.

Fuente / Source: Security Detection Lab v0.1.0, commit `dc31cf4c138123775185c41612e139082d383070`.

| Captura / Capture | ES | EN | Uso sugerido / Suggested use |
| --- | --- | --- | --- |
| [01-auth-burst.jpg](images/01-auth-burst.jpg) | Una alerta con cinco eventos de evidencia | One alert, five evidence events | Portafolio + GitHub / Portfolio + GitHub |
| [02-denied-ports.jpg](images/02-denied-ports.jpg) | Cinco puertos denegados, una señal | Five denied ports, one signal | GitHub |
| [03-window-and-duplicates.jpg](images/03-window-and-duplicates.jpg) | El borde cuenta; el duplicado no | The boundary counts; the duplicate does not | GitHub |
| [04-expectation-mismatch.jpg](images/04-expectation-mismatch.jpg) | Una expectativa incorrecta falla | An incorrect expectation fails | Portafolio + GitHub / Portfolio + GitHub |
| [05-verification.jpg](images/05-verification.jpg) | 126 pruebas y nueve escenarios verificados | 126 tests and nine verified scenarios | GitHub |

## 1. Autenticación / Authentication

**ES:** Replay de `auth-burst`: `fail-5` dispara una alerta con evidencia `fail-1` a `fail-5`, umbral 5 y ventana de 300 segundos. El sexto fallo califica durante el cooldown y se suprime: dos disparadores califican, una alerta se emite y uno se suprime. Evaluación `passed`, salida 0. Visor de evidencia de eventos sintéticos, sin conexión a SIEM.

**EN:** The `auth-burst` replay emits one alert triggered by `fail-5`, with `fail-1` through `fail-5` as evidence, threshold 5 and a 300-second window. The sixth qualifying failure is suppressed during cooldown: two qualifying triggers, one emitted alert and one suppressed trigger. Evaluation `passed`, exit 0. Evidence viewer for synthetic events, with no SIEM connection.

**Alt ES:** Tabla de seis fallos de autenticación, cinco IDs de evidencia y métricas con una supresión.

**Alt EN:** Six authentication failures, five evidence IDs and rule metrics showing one suppression.

## 2. Puertos denegados / Denied ports

**ES:** `denied-ports` cuenta cinco puertos distintos (22, 80, 443, 445 y 3389) para el mismo origen, destino y transporte. `deny-5` dispara `denied-port-fanout`, con evidencia `deny-1` a `deny-5`, umbral 5 y ventana de 60 segundos. Son eventos sintéticos de denegación; no prueban que los puertos estén abiertos ni que haya ocurrido un ataque.

**EN:** `denied-ports` counts five distinct ports (22, 80, 443, 445 and 3389) for the same source, destination and transport. `deny-5` triggers `denied-port-fanout`, with `deny-1` through `deny-5` as evidence, threshold 5 and a 60-second window. These synthetic deny events do not establish open ports or an attack.

**Alt ES:** Cinco eventos deny con sus puertos, agrupación, umbral, ventana y evidencia completa.

**Alt EN:** Five deny events with their ports, grouping, threshold, window and complete evidence.

## 3. Ventana y duplicados / Window and duplicates

**ES:** Dos pruebas independientes: `window-boundary` incluye un evento exactamente 300 segundos anterior al disparador; el evento posterior llega 301 segundos después del anterior y no genera otra alerta. Su umbral es 2. En `duplicate-replay`, 7 registros se convierten en 6 eventos únicos y una alerta; se elimina una copia idéntica de `fail-6`. Ambos casos pasan con salida 0.

**EN:** Two independent cases: `window-boundary` includes an event exactly 300 seconds before the trigger; the later event arrives 301 seconds after its predecessor and emits no further alert. Its threshold is 2. In `duplicate-replay`, 7 records become 6 unique events and one alert; one identical copy of `fail-6` is removed. Both cases pass with exit 0.

**Alt ES:** Timestamps de los tres eventos de frontera y conteos 7 registros, 6 únicos, 1 duplicado eliminado, 1 alerta.

**Alt EN:** Three boundary event timestamps and counts of 7 records, 6 unique events, 1 duplicate removed and 1 alert.

## 4. Discrepancia deliberada / Deliberate mismatch

**ES:** `expectation-mismatch` espera cero alertas aunque el replay produce una. La evaluación es `failed`, identifica `auth-failure-burst` y `fail-5` como alerta inesperada y la CLI sale con código 1. Es un fallo deliberado del fixture que el verificador exige; demuestra que el contrato puede rechazar resultados incorrectos.

**EN:** `expectation-mismatch` expects zero alerts while the replay produces one. Evaluation is `failed`, identifies `auth-failure-burst` and `fail-5` as the unexpected alert, and the CLI exits 1. This is a deliberate fixture failure required by the verifier, demonstrating that the contract can reject incorrect results.

**Alt ES:** Evaluación JSON completa con esperado 0, actual 1, estado failed y salida CLI 1.

**Alt EN:** Complete evaluation JSON with expected 0, actual 1, failed status and CLI exit 1.

## 5. Verificación / Verification

**ES:** Ejecución local independiente: 126 pruebas pasan, Ruff no detecta problemas y los ocho archivos Python revisados ya tienen formato correcto. La matriz verifica nueve escenarios CLI, incluidos `benign` con cero alertas, la discrepancia deliberada con salida 1 y un ID con contenido contradictorio rechazado con salida 2, sin crear salida. La copia instalada coincide con la fuente del commit. Estas pruebas no miden precisión o recall en datos reales.

**EN:** Independent local execution: 126 tests pass, Ruff reports no issues and the eight checked Python files are already formatted. The matrix verifies nine CLI scenarios, including `benign` with zero alerts, the deliberate mismatch with exit 1 and conflicting payloads for one ID rejected with exit 2 without creating output. The installed package matches the commit source. These tests do not measure precision or recall on real-world data.

**Alt ES:** Salida real de pytest, comprobaciones Ruff y matriz completa de nueve escenarios CLI.

**Alt EN:** Actual pytest output, Ruff checks and the complete nine-scenario CLI matrix.
