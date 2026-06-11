"""
AI Triage with Multi-Provider Fallback — Find Evil Hackathon
Based on Elliot Cybersecurity Lab's ai_triage.py
"""

import json
import os
import sys
import requests
from pathlib import Path
from typing import Optional

# Add tools to path
sys.path.append(str(Path(__file__).parent))

try:
    from secret_vault import SecretVault
except ImportError:
    SecretVault = None


PROVIDERS = {
    "openrouter": {
        "base": "https://openrouter.ai/api/v1",
        "model": os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b:free"),
        "env_key": "OPENROUTER_API_KEY",
        "extra_headers": {
            "HTTP-Referer": "https://github.com/find-evil-hackathon",
            "X-Title": "Find Evil Hackathon",
        },
        "fallback_models": [
            "nvidia/nemotron-3-super-120b-a12b:free",
            "minimax/minimax-m2.5:free",
            "z-ai/glm-4.5-air:free",
            "openai/gpt-oss-20b:free",
            "meta-llama/llama-3.3-70b-instruct:free",
        ],
    },
    "nvidia_nim": {
        "base": "https://integrate.api.nvidia.com/v1",
        "model": os.getenv("NVIDIA_MODEL", "meta/llama-3.3-70b-instruct"),
        "env_key": "NVIDIA_NIM_API_KEY",
    },
    "moonshot": {
        "base": "https://api.moonshot.cn/v1",
        "model": os.getenv("KIMI_MODEL", "moonshot-v1-8k"),
        "env_key": "KIMI_API_KEY",
    },
    "moonshot_global": {
        "base": "https://api.moonshot.ai/v1",
        "model": os.getenv("KIMI_MODEL", "kimi-k2-0711-preview"),
        "env_key": "KIMI_API_KEY",
    },
    "zai": {
        "base": "https://api.z.ai/api/paas/v4",
        "model": os.getenv("ZAI_MODEL", "glm-4.5-flash"),
        "env_key": "ZAI_API_KEY",
    },
    "zhipu": {
        "base": "https://open.bigmodel.cn/api/paas/v4",
        "model": os.getenv("ZHIPU_MODEL", "glm-4-flash"),
        "env_key": "ZHIPU_API_KEY",
    },
}

DEFAULT_PROVIDER = os.getenv("DAVI_TRIAGE_PROVIDER", "openrouter")


def _get_key(provider: str) -> Optional[str]:
    info = PROVIDERS.get(provider)
    if not info:
        return None
    env_val = os.getenv(info["env_key"])
    if env_val:
        return env_val
    try:
        if SecretVault:
            return SecretVault().get(info["env_key"])
    except Exception:
        pass
    return None


def health(provider: str = DEFAULT_PROVIDER) -> tuple[bool, str]:
    info = PROVIDERS.get(provider)
    if not info:
        return False, f"unknown provider: {provider}"
    key = _get_key(provider)
    if not key:
        return False, f"no API key for {provider} (env={info['env_key']} also empty)"
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    headers.update(info.get("extra_headers", {}))
    try:
        r = requests.post(
            f"{info['base']}/chat/completions",
            headers=headers,
            json={
                "model": info["model"],
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
                "temperature": 0,
            },
            timeout=20,
        )
    except requests.RequestException as exc:
        return False, f"network error: {exc}"
    if r.status_code == 200:
        return True, f"{provider}/{info['model']} OK"
    if r.status_code == 401:
        return False, f"{provider}: 401 unauthorized — key not valid for this endpoint (try a different provider)"
    return False, f"{provider}: HTTP {r.status_code} — {r.text[:200]}"


def _is_fatal_http(status: int) -> bool:
    return status in (400, 401, 403)


def _provider_chain(primary: str | None = None) -> list[str]:
    if primary:
        return [primary]
    raw = os.getenv("OLAB_FALLBACK_PROVIDERS")
    if raw:
        try:
            chain = json.loads(raw)
            if isinstance(chain, list) and chain:
                return [str(p) for p in chain]
        except Exception:
            pass
    if DEFAULT_PROVIDER != "nvidia_nim":
        return [DEFAULT_PROVIDER, "nvidia_nim"]
    return ["nvidia_nim", "openrouter"]


def _model_fallback_report(provider: str) -> tuple[list[str], str]:
    info = PROVIDERS[provider]
    models = [info["model"]] + list(info.get("fallback_models", []))
    stub = f"Provider details for {provider}:\n"
    stub += f"- base_url: {info.get('base_url', info['base'])}\n"
    stub += f"- models: {', '.join(models)}\n"
    stub += f"- missing_api_key: {not bool(_get_key(provider))}"
    return models, stub


def _post_chat(provider: str, model: str, prompt: str, timeout: int = 90) -> requests.Response:
    info = PROVIDERS[provider]
    key = _get_key(provider)
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    headers.update(info.get("extra_headers", {}))
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Eres un experto en seguridad informática y análisis de malware."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
    }
    return requests.post(f"{info['base']}/chat/completions", headers=headers, json=payload, timeout=timeout)


def _build_prompt(candidate_path: str, findings_path: str | None = None, strace_path: str | None = None) -> str:
    code = Path(candidate_path).read_text(encoding="utf-8", errors="ignore")
    findings = (
        Path(findings_path).read_text(encoding="utf-8", errors="ignore")
        if findings_path and Path(findings_path).exists()
        else ""
    )
    telemetry = (
        Path(strace_path).read_text(encoding="utf-8", errors="ignore")
        if strace_path and Path(strace_path).exists()
        else ""
    )
    if len(telemetry) > 5000:
        telemetry = telemetry[:2500] + "\n[... TRUNCATED ...]\n" + telemetry[-2500:]
    return f"""Eres un Experto en Ciberseguridad de Elite (Elliot-OSINT). Tu tarea es realizar el triaje de un 'Skill' sospechoso detectado en el laboratorio.

### CÓDIGO DEL CANDIDATO:
```
{code}
```

### HALLAZGOS DE ESCÁNERES ESTÁTICOS:
{findings or "(sin hallazgos suministrados)"}

### TELEMETRÍA DE COMPORTAMIENTO (STRACE):
{telemetry or "(sin telemetría suministrada)"}

### INSTRUCCIONES:
1. Analiza el código buscando intenciones maliciosas (exfiltración, backdoors, inyección).
2. Cruza el código con la telemetría de strace para confirmar si las intenciones se materializaron.
3. Clasifica el riesgo como: CRITICAL, HIGH, MEDIUM o LOW.
4. Explica brevemente POR QUÉ es peligroso en términos sencillos para el usuario.
5. Sugiere una acción inmediata de remediación.
6. Mapea, si aplica, técnicas MITRE ATT&CK y/o ATLAS implicadas.

Responde en formato MARKDOWN profesional.
"""


def perform_triage(
    candidate_path: str,
    findings_path: str | None = None,
    strace_path: str | None = None,
    provider: str | None = None,
) -> str:
    resolved = provider or DEFAULT_PROVIDER
    providers = _provider_chain(provider)
    if not providers:
        providers = [resolved]

    if resolved not in PROVIDERS:
        models, provider_report = _model_fallback_report(resolved)
        return (
            "🔴 unknown provider: {} | "
            "available: openrouter, nvidia_nim, moonshot, moonshot_global, zai, zhipu\n"
        ).format(resolved) + provider_report

    prompt = _build_prompt(candidate_path, findings_path, strace_path)
    last_err = None
    provider_statuses = []

    for provider in providers:
        if provider not in PROVIDERS:
            provider_statuses.append(f"⚠️ skipped provider '{provider}': not in PROVIDERS registry")
            continue

        key = _get_key(provider)
        if not key:
            provider_statuses.append(
                f"⚠️ skipped provider '{provider}': missing API key ({PROVIDERS[provider]['env_key']})"
            )
            continue

        info = PROVIDERS[provider]
        candidates = [info["model"]] + list(info.get("fallback_models", []))

        for model in candidates:
            try:
                print(f"🤖 [{provider}] triaging via {model}…")
                r = _post_chat(provider, model, prompt)
                if r.status_code == 200:
                    return r.json()["choices"][0]["message"]["content"]
                if r.status_code in (429, 502, 503, 504) and not _is_fatal_http(r.status_code):
                    last_err = f"{r.status_code} on {provider}/{model}"
                    print(f"   ↻ {last_err} — trying fallback within {provider}")
                    continue
                provider_statuses.append(f"🔴 {provider}/{model}: HTTP {r.status_code} — {r.text[:300]}")
                if _is_fatal_http(r.status_code):
                    return "\n".join(provider_statuses)
                break
            except requests.RequestException as exc:
                last_err = f"network error on {provider}/{model}: {exc}"
                print(f"   ↻ {last_err}")
                continue

        provider_statuses.append(f"ℹ️ provider '{provider}' exhausted or skipped.")

    failed_models, provider_report = _model_fallback_report(resolved)
    last_err_text = last_err or "unknown error"
    return (
        "🔴 all providers/models failed for triage\n"
        f"- last_error: {last_err_text}\n"
    ) + "\n".join(provider_statuses) + "\n\n" + provider_report


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="AI triage with provider fallback")
    ap.add_argument("candidate", nargs="?", help="Path to candidate file to triage")
    ap.add_argument("findings", nargs="?", help="Path to scanner findings (optional)")
    ap.add_argument("strace", nargs="?", help="Path to strace telemetry (optional)")
    ap.add_argument("--health", action="store_true", help="Validate API auth and exit")
    ap.add_argument("--provider", default=DEFAULT_PROVIDER, choices=list(PROVIDERS), help=f"LLM provider (default: {DEFAULT_PROVIDER})")
    args = ap.parse_args()

    if args.health:
        ok, msg = health(args.provider)
        print(("✅ " if ok else "🔴 ") + msg)
        sys.exit(0 if ok else 1)

    if not args.candidate:
        ap.error("candidate file required (or pass --health)")

    report = perform_triage(args.candidate, args.findings, args.strace, provider=args.provider)
    print("\n" + "=" * 50)
    print(f"      REPORTE DE TRIAJE IA ({args.provider.upper()})")
    print("=" * 50 + "\n")
    print(report)