# Security & Secrets Policy

## Incident history

**2026-06-11 (commit `ff67cca`):** A real NVIDIA NIM API key was committed to
`SESSION_HANDOFF.md` and pushed to `origin/grounding-audit-competition-pass`.
The file was later removed from working tree and scrubbed from history with
`git filter-repo --path SESSION_HANDOFF.md --invert-paths` on 2026-06-15. The
exposed key was revoked by the owner at build.nvidia.com. The repo history
on `origin` was then force-pushed to remove the file.

**Lesson:** session handoff files are convenient for the developer and dangerous
to publish. Keep them OUT of the public branch, or redact any keys before
commit.

## What goes in the public repo

- ✅ Source code, tests, scanners, documentation
- ✅ Demo video links (via `gh release`), accuracy report JSON, audit trail DB
- ✅ Architecture diagrams, dataset documentation, accuracy metrics
- ❌ **Never** real API keys, session handoff files with credentials, or `.env`
  with live values
- ❌ **Never** internal URLs, lab paths with credentials, or private repo paths

## Pre-commit check (manual)

Before `git push` to `origin/grounding-audit-competition-pass`:

```bash
# Should return NOTHING for a clean repo:
grep -rE "nvapi-[A-Za-z0-9_-]{30,}|sk-or-v1-[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{40,}" \
  --include="*.py" --include="*.md" --include="*.sh" --include="*.json" --include="*.yml" \
  --include=".env*" .
```

If this returns matches, `git rm` the file, re-commit, and verify with
`git log --all -p -S "<key-prefix>"` (should be empty).

## Pre-push hardening (recommended)

Add a `pre-commit` framework hook that runs `gitleaks` or `detect-secrets`.
This is not yet wired in this repo (TODO if you do this again).
