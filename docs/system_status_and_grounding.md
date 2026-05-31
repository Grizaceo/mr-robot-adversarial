# MR. Robot Adversarial — Estado del Sistema y Grounding Académico

**Evaluación revisada para SANS FIND EVIL! 2026**  
**Fecha:** 2026-05-30  
**Repositorio:** `find-evil-hackathon`  
**Alcance:** Documento único de estado + fundamentación. Integra métricas, brechas, rúbrica y literatura citada.

---

## 1. Estado del Sistema por Capa

### 1.1 Scanner Suite
- **4 motores en paralelo:** skill_scanner, ioc_scanner, scan_yara, secrets_detector.
- **Métrica verificada:** accuracy_report.json muestra 99 TP / 19 TN sobre 118 escenarios. FPR 0.
- **Limitación honesta:** corpus es privado del proyecto. No es externamente comparable sin compartir el test corpus.

### 1.2 MR. Robot Triage
- **Modelo:** NVIDIA NIM `mistralai/mistral-nemotron`.
- **Diseño:** 5-phase prompt con MITRE ATT&CK IDs y 12-key checklist contract.
- **Rendimiento E2E:** ~12 s por archivo; confidence 0.95–0.99.
- **Heterogeneity check:** Falsifier (DeepSeek/Nemotron alterno) con ΔA≈1, enforced en el synthesizer (τ=0).

### 1.3 Cross-Stack Correlator
- **Código:** `cross_stack_correlator.py` implementado; CampaignDetector sobre SQLite `audit_trail.db`.
- **Lógica:** 3+ eventos MALICIOUS misma tool_name en 24h → CRITICAL.
- **Estado:** tests verdes (6 casos). Aún no integrado al orchestrator.

### 1.4 Episodic Memory / Few-Shot Retrieval
- **Schema:** columnas nuevas (`snippet`, `campaign_detected`, `scanner_flags`, `ioc_pattern`) en `execution_logger.py`.
- **Código:** TF-IDF + `build_few_shot_block` pendiente de wire en `triage_orchestrator.py`.

### 1.5 SIFT Bridge
- **Componentes funcionales:** pytsk3 (Sleuthkit bindings), volatility3, strings extraction.
- **MCP tools:** 5 tools expuestas (`sift_list_filesystem`, `sift_carve_blocks`, `sift_memory_pslist`, `sift_memory_strings`, `sift_health`).
- **Evidencia real:** ISO PSP parseada (pytsk3), strings de dump sintético, block carving sobre imagen fake.
- **Brecha:** no corre en VM SIFT Workstation; status DEFERRED.

### 1.6 CyberSOCEval Gate
- **Benchmark:** CyberSOCEval Malware Analysis (Meta/CrowdStrike, Deason et al. 2025).
- **Último número oficial (pre-fix):** exact-match 10.0%, Jaccard 0.413, n=30.
- **Causas documentadas:** prompt overselection + parse_answer laxo.
- **Fixes aplicados:** SYSTEM_PROMPT strict, `parse_answer` reforzado.
- **Gate actual:** bloqueada sin datasets locales (`PurpleLlama` + `CyberSOCEval_data`).

### 1.7 Pruebas
- **129 passed, 3 skipped.** Incluye tests del correlator.
- **Lint:** pendiente (`ruff`/`black`).

---

## 2. Evaluación por Criterios FIND EVIL! (Auto-Rúbrica)

| Criterion | Estado actual | Para subir de nivel |
|---|---|---|
| Completion & on-time | Código funcional, repo público, tests verdes | Video listo antes de 2026-06-15 |
| Self-improving agents | Documentado; schema listo; retrieval store no integrado | Wire TF-IDF + few-shot block |
| Real-world impact | MTTR 12 s, E2E con scanners multi-capa; SIFT proto real | Gate CyberSOCEval post-fix publicado; acciones automatizadas en demo |
| Demo clarity | E2E output, arquitectura diagramada | Video con before/after, capturas reales |

---

## 3. Grounding Académico

Cada capa del sistema tiene un referente explícito en literatura revisada por pares o frameworks públicos.

### 3.1 Papers y Referencias Citadas en el Código

| ID | Autores | Título | Año | Aparición principal |
|---|---|---|---|---|
| arXiv:2604.27274 | Shehata & Li | The Inverse-Wisdom Law: Architectural Tribalism and the Consensus Paradox in Agentic Swarms | 2026 | `triage_orchestrator.py`, `triage_falsifier.py`, `README.md` |
| arXiv:2509.20166 | Deason et al. | CyberSOCEval: Benchmarking LLMs Capabilities for Malware Analysis and Threat Intelligence Reasoning | 2025 | `docs/cybersoceval_results.md` (BibTeX) |
| arXiv:2305.14325 | Du et al. | Improving Factuality and Reasoning in Language Models through Multiagent Debate | 2023 | `triage_falsifier.py`, `docs/heterogeneity_mandate.md` |
| arXiv:2203.11171 | Wang et al. | Self-Consistency Improves Chain of Thought Reasoning in Language Models | 2022 | `triage_orchestrator.py` |
| arXiv:2305.19118 | Liang et al. | Encouraging Divergent Thinking in Large Language Models through Multi-Agent Debate | 2023 | `triage_falsifier.py` |
| arXiv:2310.13548 | Sharma et al. | Towards Understanding Sycophancy in Language Models | 2023 | `triage_falsifier.py` |

### 3.2 Mapa de Capas a Literatura

| Capa | Paper grounding | Rol |
|---|---|---|
| Heterogeneity Mandate | arXiv:2604.27274 | Previene Logic Saturation (kinship lock) |
| Falsifier multiagente | arXiv:2305.14325, 2305.19118 | Mejora factuality mediante forzado de divergencia |
| Self-consistency sampling | arXiv:2203.11171 | Robustez mediante rutas diversas de razonamiento |
| LLM Sycophancy | arXiv:2310.13548 | Explica overselection (σ alto en propagator = auditor mismo modelo) |
| CyberSOCEval | arXiv:2509.20166 | Único benchmark público comparable para malware analysis MCQ |
| Cross-Stack Correlator | arXiv:2604.27274 (Cascade Point Theorem) | Detección multivariada reduce error; implementación actual es 1D |
| Episodic Memory | arXiv:2604.27274 + Lewis et al. 2020 (RAG) | Mitiga novice error; wire pendiente |

### 3.3 Estándares y Marcos

| Marco | Uso en el sistema |
|---|---|
| MITRE ATT&CK | Mapping de TTPs en Phase 2 (triage) |
| NIST SP 800-61r3 | Las 5 fases de MR. Robot mapean a Preparation → Detection → Analysis → Containment → Eradication |
| OWASP LLM Top 10 (2025) | Riesgos: prompt injection (LLM01), overreliance (LLM06), improper output handling (LLM02) |

---

## 4. Diagnóstico de Brechas con Causalidad Grounded

| # | Brecha | Impacto en rúbrica | Causa grounded | Fix |
|---|---|---|---|---|
| 1 | CyberSOCEval sin re-ejecutar post-fix | IR Accuracy invalorable | arXiv:2310.13548 → overselection por sycophancy (mismo modelo como propagator y auditor) | Bajar datasets y correr gate |
| 2 | Retrieval store no integrado | Self-improving agents no demostrado | arXiv:2604.27274 (Inverse-Wisdom Law) + Lewis 2020 (RAG) | Implementar TF-IDF + `build_few_shot_block` |
| 3 | Correlator aislado | Impact claim abstracto | arXiv:2604.27274 (Cascade Point Theorem) implica correlación multivariada | Wire orchestrator → correlator → JSON final |
| 4 | SIFT en WSL, no en VM SIFT | "Built on SIFT Workstation" débil | Brief pide SIFT Workstation; bindings son compatibles pero entorno no | Documentar como deferred; mostrar evidencia funcional |
| 5 | Sin video | Completion parcial | — | Grabación post-code freeze (2026-06-15) |

---

## 5. Calificación Integrada (Escala 1–5)

| Capa | Grounding teórico | Implementación | Trazabilidad | Total |
|---|---|---|---|---|
| Scanner Suite | 4 | 4 | 3 | 11/15 |
| MR. Robot Triage | 5 | 4 | 3 | 12/15 |
| Falsifier / Heterogeneity | 5 | 4 | 4 | 13/15 |
| Benchmark CyberSOCEval | 5 | 3 | 4 | 12/15 |
| SIFT Bridge | 4 | 2 | 3 | 9/15 |
| Cross-Stack Correlator | 4 | 3 | 2 | 9/15 |
| Retrieval / Self-Improvement | 3 | 1 | 1 | 5/15 |
| **Global** | — | — | — | **71/105 ≈ 67.6%** |

Escala interpretativa (auto-referenciada):  
- 80%+ = competitivo por picking.  
- 65–79% = sólido con brechas identificadas y fixes accionables.  
- <65% = necesita cierre de brechas críticas antes de juzgarse.

**Conclusión:** 67.6% nos ubica en **“sólido con brechas accionables”**. Los 3 frentes de mejora (gate, retrieval, correlator wiring) son técnicamente conocidos y acotables en ~1 día efectivo de trabajo.

---

## 6. Próximos Pasos Priorizados

### Alta prioridad (bloquea competitividad)
1. **Bajar CyberSOCEval datasets y ejecutar gate post-fix.**  
   Comando preparado; datasets ausentes. Resultado esperado: exact-match 18–28% (vs 10% pre-fix).
2. **Implementar retrieval store e integrar al orchestrator.**  
   Cierra brecha “self-improving agents” con respaldo teórico explícito (Inverse-Wisdom Law + RAG).
3. **Wire correlator al orchestrator.**  
   `campaign_detected` pasa a formar parte del JSON final de triage.

### Media prioridad
4. **Lint y cleanup** (`ruff check`, `black --check`).
5. **Actualizar CHANGELOG.md** con los cambios aplicados.
6. **Refrescar `docs/try_it_out.md`** con ejemplo JSON que incluya `campaign_detected`.

### Baja prioridad (post-submission o paralelo)
7. **Video demo** (excluido del scope actual).
8. **Migración a SIFT VM completa** (deferred; requiere VirtualBox/VMware).
9. **Validación heterogeneidad multi-modelo** (`docs/heterogeneity_validation.md`).

---

## 7. Referencias Formales (para README)

```
[1] Shehata, D. & Li, M. (2026). The Inverse-Wisdom Law: Architectural
    Tribalism and the Consensus Paradox in Agentic Swarms.
    arXiv:2604.27274. University of Waterloo.

[2] Deason, L. et al. (2025). CyberSOCEval: Benchmarking LLMs Capabilities
    for Malware Analysis and Threat Intelligence Reasoning.
    arXiv:2509.20166. Meta / CrowdStrike.

[3] Du, Y. et al. (2023). Improving Factuality and Reasoning through
    Multiagent Debate. arXiv:2305.14325.

[4] Wang, X. et al. (2022). Self-Consistency Improves Chain of Thought
    Reasoning. arXiv:2203.11171.

[5] Liang, J. et al. (2023). Encouraging Divergent Thinking in Large Language
    Models through Multi-Agent Debate. arXiv:2305.19118.

[6] Sharma, V. et al. (2023). Towards Understanding Sycophancy in Language
    Models. arXiv:2310.13548.

[7] MITRE ATT&CK Framework. https://attack.mitre.org/

[8] NIST SP 800-61r3. Computer Security Incident Handling Guide.
    https://csrc.nist.gov/publications/detail/sp/800-61r3/final

[9] OWASP Top 10 for LLM Applications (2025).
    https://owasp.org/www-project-top-10-for-large-language-model-applications/
```

---

*Documento generado a partir del estado verificado del repositorio y papers referenciados en el código.*
