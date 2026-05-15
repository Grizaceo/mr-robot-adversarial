# Architectural Guardrails — what is enforced where

The SANS FIND EVIL! 2026 rubric explicitly distinguishes
**architectural guardrails** (enforced by code, types, processes,
filesystem isolation) from **prompt-based guardrails** (enforced by
text in a system prompt that the LLM may or may not follow).

This document catalogues every guardrail in the pipeline against that
distinction, with the exact file:line that implements it.

## Summary

| Category | Count | Notes |
|---|---|---|
| **Architectural** (cannot be bypassed by clever prompting) | 9 | Implemented in code; LLM has no authority over them |
| **Hybrid** (architectural envelope + prompt directive inside it) | 3 | Both layers must fail for the guardrail to fail |
| **Prompt-based** (text the model may follow) | 5 | Soft guardrails; assume failure is possible |

The intent is to make the architectural layer *the* defensive boundary
and keep the prompt-based layer for *quality of analysis*, not security.

---

## Architectural guardrails

### A1 — Path validation
- **Where:** `mcp_tools.py:39 validate_target_file`
- **What:** rejects symlinks, non-files, unreadable files, paths outside
  `MR_ROBOT_ALLOWED_ROOTS`, and oversize inputs (`MAX_INPUT_BYTES`).
- **Bypass route:** none from inside the LLM — runs before any LLM call.

### A2 — File-size cap on LLM ingestion
- **Where:** `agents/mr_robot/triage.py` `MAX_TRIAGE_FILE_BYTES` (default 50 KB).
- **What:** large files short-circuit to `verdict="INCONCLUSIVE"` without
  ever entering the LLM context. Prevents context-overflow DoS and
  smuggling-via-bulk.
- **Bypass route:** none from input content; only by raising the env var.

### A3 — Prompt-injection sentinel boundary
- **Where:** `prompt_injection_defense.safe_wrap` +
  `agents/mr_robot/triage.py:_build_prompt` +
  `triage_falsifier.py:_build_falsification_prompt`.
- **What:** all candidate-file content is wrapped in
  `<file_under_review filename=... sha256=... length=...> … </file_under_review>`
  before reaching the LLM. Internal occurrences of the closing sentinel
  are mechanically defanged to `</file_under_review_ESCAPED>` so the
  adversary cannot close the boundary early and inject text *outside* it.
- **Bypass route:** the sentinel itself is text, so a smart enough LLM
  could still ignore it. Combined with **H1** below to harden.

### A4 — Subprocess isolation per scanner
- **Where:** `mcp_tools._run_scanner` runs each scanner as a separate
  `subprocess.run` with its own JSON output file and a timeout.
- **What:** a scanner crash, hang, or exfiltration attempt is contained
  to that subprocess and cannot poison Python in-process state.

### A5 — Scanner output sanitization
- **Where:** `mcp_tools._run_scanner` reads scanner output from disk as
  JSON, never `eval()`s it; invalid JSON returns an error stub.
- **What:** a malicious scanner output cannot inject code.

### A6 — Rule-based synthesizer (τ=0)
- **Where:** `triage_orchestrator._compute_synthesizer_verdict`.
- **What:** the final verdict is computed by deterministic rules over
  the triage report, falsifier result, scanner findings, and
  heterogeneity status. **No LLM is consulted at the synthesis step.**
  Per Shehata & Li (2026), this is the architectural property that
  prevents kinship-lock cascades. The synthesizer is the only authority
  for the verdict the user sees.
- **Bypass route:** none from the LLM.

### A7 — Audit-trail logging (SQLite WAL)
- **Where:** `execution_logger.get_logger` writes to
  `logs/audit_trail.db` (WAL mode).
- **What:** every tool call (`scan_file`, `triage_artifact`,
  `falsify_triage`, `orchestrate_complete`, **`prompt_injection_detected`**)
  produces a row with tool name, inputs, outputs, verdict, severity,
  duration. JSON-exportable. Concurrent-safe by SQLite WAL.
- **Bypass route:** none — every code path that talks to an LLM also
  writes to the audit DB.

### A8 — Heterogeneity check at the synthesizer
- **Where:** `triage_orchestrator._check_heterogeneity` +
  `_detect_family`.
- **What:** propagator and auditor model families are detected from
  model name strings. If they collapse to the same family
  (e.g. OpenRouter falls back to a Nemotron-family model on the
  Falsifier path), the synthesizer marks the rationale with a
  `kinship_lock_risk: HIGH` flag and writes a
  `kinship_lock_warning` row to the audit trail. The flag is a
  first-class field on the report, not a prompt nudge.

### A9 — Bounded correction iterations
- **Where:** `triage_orchestrator.MAX_CORRECTION_ITERATIONS = 2`.
- **What:** the self-correction loop terminates after at most 2 cycles
  regardless of LLM behavior. Per Shehata & Li (2026), beyond this
  same-family recursion amplifies rather than reduces error.
- **Bypass route:** none — enforced by a `for` loop.

---

## Hybrid guardrails (architectural envelope + prompt directive)

### H1 — Trust-boundary notice on the sentinel
- **Architectural part:** the sentinel tag itself (A3).
- **Prompt part:** `prompt_injection_defense.TRUST_BOUNDARY_NOTICE`,
  appended to both `SYSTEM_PROMPT` (triage) and
  `FALSIFIER_SYSTEM_PROMPT`. Tells the LLM that anything inside the
  sentinel is hostile data, that injection attempts inside it are
  *evidence* (to be reported, not obeyed), and that the 5-phase
  workflow is the only source of authority.
- **Why hybrid:** the sentinel mechanically delimits the data; the
  notice tells the LLM the social meaning of that delimitation.
  Either alone is weaker.

### H2 — Detector-side flagging of injection attempts
- **Architectural part:** `prompt_injection_defense.scan` runs over
  every byte before the LLM sees it, and the result is exposed via
  `get_last_injection_scan` and written to `_meta.prompt_injection_scan`.
- **Prompt part:** the system prompt instructs the LLM to *also*
  flag injection attempts as findings with category
  `prompt_injection_attempt`. The two flag paths must agree.
- **Why hybrid:** if the regex misses a novel pattern, the LLM may
  still notice and flag it from inside the sentinel; if the LLM is
  too compliant, the regex still records the attempt to the audit
  trail. **Two paths, one bus.**

### H3 — Framework-aware false-positive refutation
- **Architectural part:** the Falsifier always runs (when triage
  confidence is below the high-confidence cutoff) and its output
  feeds the synthesizer.
- **Prompt part:** the Falsifier prompt lists framework-safe
  patterns (Django auto-escape, React `{var}`, ORM
  parameterization, etc.) and instructs the auditor to refute
  findings that match them.
- **Why hybrid:** the architectural cycle guarantees the refutation
  *runs*; the prompt guarantees the auditor *checks the right
  patterns* when it does.

---

## Prompt-based guardrails (soft layer)

The following are good practice and improve analysis quality, but
none of them are a defensive boundary — assume an injection that
gets past the architectural layer can disable them.

| ID | What | Where |
|---|---|---|
| P1 | 5-phase review workflow (Input / Surface / Checklist / Verification / Audit) | `agents/mr_robot/triage.py:SYSTEM_PROMPT` |
| P2 | Confidence levels HIGH/MEDIUM/LOW with explicit "only report HIGH" rule | same |
| P3 | Framework-aware FP reduction patterns | same |
| P4 | Falsifier "be honest, don't falsify for the sake of it" directive | `triage_falsifier.py:FALSIFIER_SYSTEM_PROMPT` |
| P5 | MITRE ATT&CK mapping instructions in the schema | `agents/mr_robot/triage.py:SYSTEM_PROMPT` |

---

## How the guardrails interact

The defensive picture has two independent failure modes:

1. **Injection that reaches the LLM context.** A1 stops most paths;
   A2 caps the volume; A3 wraps everything in a sentinel; A5 keeps
   scanner JSON inert. To reach the LLM context with injection
   content, the adversary has to author content inside a small file
   that lives in an allowed root. **That is exactly the threat model
   for a triage system, so we treat it as expected.** The defense
   then becomes H1+H2: the LLM is told the wrapped content is
   hostile, and the architectural scan records every attempt before
   the LLM sees the content.

2. **Sycophantic LLM-on-LLM review.** A6 (rule-based synthesizer)
   means the LLM cannot decide the final verdict no matter how
   confidently it agrees with itself. A8 (heterogeneity check) +
   A9 (bounded iterations) cap the damage from same-family
   collapse. The Shehata & Li (2026) heterogeneity mandate is
   enforced *architecturally at the synthesizer*, not prompted at
   the LLMs.

A bypass of the architectural layer (e.g., a future regex miss in
A3) downgrades to prompt-based defense (H1). A bypass of both is a
disclosed limitation.

---

## Known gaps (deliberately disclosed)

| Gap | Status | Tracking |
|---|---|---|
| The A3 regex set is finite; novel injection templates may slip through | Documented, mitigated by H1/H2 layered defense | grow patterns over time |
| No semantic LLM-based injection classifier (à la PromptArmor) | Considered, deferred — would add a third LLM call | future work |
| Scanner subprocess timeout is per-scanner, not aggregate | Acceptable for current workload (~200ms per scanner) | revisit if scanners grow |
| FPR 15.8% on benign control set (3 of 19) | Disclosed in `docs/accuracy_report.json`; root cause for each FP listed in `CHANGELOG.md` | tune scanner rules |

---

## References

- MITRE ATLAS v5.4.0 (Feb 2026): 14 new agentic techniques including
  indirect prompt injection and tool-invocation abuse.
- Shehata & Li (2026), arXiv:2604.27274: heterogeneity mandate.
- OWASP LLM Top 10 (2025): LLM01 Prompt Injection taxonomy.
- Unit42 (Palo Alto, 2026): indirect prompt injection in production
  triage agents — the npm/Claude-Code-triage incident this guardrail
  set is designed to prevent.
- PromptArmor (ICLR 2026): LLM-as-preprocessor for injection
  detection; cited as inspiration for the H2 two-path flagging.
