# MR. Robot Adversarial — E2E Test Results (Day 4)

**Date:** 2026-05-14
**Provider:** NVIDIA NIM (mistralai/mistral-nemotron)
**Pipeline:** scan_file → triage_artifact → audit_trail

## Results

| # | File | Scan Verdict | Scan Findings | Triage Verdict | Confidence | Severity | Triage Duration |
|---|------|-------------|---------------|----------------|------------|----------|-----------------|
| 1 | bind_shell.py | MALICIOUS | 6 | MALICIOUS | 0.95 | critical | 12.8s |
| 2 | reverse_shell.sh | MALICIOUS | 7 | MALICIOUS | 0.95 | critical | 12.1s |
| 3 | mr_robot_npm_worm.js | SUSPICIOUS | 3 | MALICIOUS | 0.95 | critical | 11.8s |
| 4 | safe_app.py | BENIGN | 0 | BENIGN | 0.99 | none | 4.6s |
| 5 | mr_robot_yaml_rce.yaml | MALICIOUS | 15 | MALICIOUS | 0.95 | critical | 12.1s |

## Key Observations

1. **npm_worm.js**: Scan dice SUSPICIOUS (solo 3 findings) pero MR. Robot dice MALICIOUS (0.95). Esto demuestra el valor del triaje AI — los scanners solos subestiman la amenaza de un worm con dead man's switch.

2. **safe_app.py**: Correctamente identificado como BENIGN por ambos (scan y triaje). 0 findings, 0.99 confidence.

3. **yaml_rce.yaml**: El scan encuentra 15 matches (muchos falsos positivos de YARA) pero MR. Robot contextualiza correctamente como un ataque de deserialización YAML.

4. **Performance**: Promedio de triaje ~12s por archivo. Scan ~200ms.

## Audit Trail

- 13 ejecuciones registradas en `logs/audit_trail.db`
- 1 health + 6 scan_file + 6 triage_artifact
- Todos los campos poblados correctamente (tool_name, input, output, duration, verdict, severity, confidence)

## Issues Found

- `scan_file` no popula `severity` ni `confidence` en el audit trail (solo `overall_verdict`). Esto es esperado pero podría mejorarse para tener un severity agregado.
- El modelo `mistral-nemotron` a veces repite el mismo MITRE ID (T1071.003) para hallazgos diferentes. No es crítico pero podría refinarse el prompt.

## Next Steps (Day 5+)

- [ ] Probar con los 15+ escenarios adversariales del cybersec-lab
- [ ] Implementar Falsifier agent (portear de AGENTIC_RIEMANN)
- [ ] Self-correction loop (confidence threshold)
- [ ] Instalar SIFT Workstation + Protocol SIFT
- [ ] Accuracy report formal (precision/recall/F1)
