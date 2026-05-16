#!/usr/bin/env python3
"""
CyberSOCEval — Threat Intelligence Reasoning (subset)
======================================================

Evaluation harness for the CyberSOCEval Threat Intelligence Reasoning subset
(588 questions, Meta + CrowdStrike joint benchmark).  Questions are presented
as images showing threat-intelligence reports; the model must answer MCQs
about actor attribution, TTPs, and indicators.

IMPORTANT — NOT EXECUTED with the default NVIDIA NIM budget.
============================================================
The threat-intel reasoning questions require MULTIMODAL inference (image +
text).  NVIDIA NIM `mistral-nemotron` is text-only.  This harness is complete
and correct but **requires a vision-capable provider** (OpenRouter + a GPT-4o
or Claude-vision model, or OpenAI directly).

To run:

    pip install openai      # or openrouter via requests
    export OPENAI_API_KEY=sk-...

    python evals/cybersoceval_threat_intel.py \\
        --questions /tmp/PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta/threat_intel/questions.json \\
        --images-root /tmp/CyberSOCEval_data/data/threat-intel \\
        --provider openai-vision \\
        --output docs/cybersoceval_threat_intel_results.json \\
        --verbose

Budget (if run):
    ~588 × 2 image+text calls × $0.01 ≈ $12 with GPT-4o-mini.
    The hackathon used NVIDIA NIM (free) which is text-only — this eval is
    documented but not executed for the submission.

Data sources:
    Questions : github.com/meta-llama/PurpleLlama / CybersecurityBenchmarks /
                datasets/crwd_meta/threat_intel/questions.json
    Images    : github.com/CrowdStrike/CyberSOCEval_data / data/threat-intel
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

OPTION_LETTERS = tuple(chr(ord("A") + i) for i in range(26))

SYSTEM_PROMPT = """\
You are a senior threat-intelligence analyst answering a multiple-choice question
about a threat-intelligence report shown as an image.

Rules:
1. Base your answer ONLY on the content visible in the image. Do not draw on
   training-data knowledge of specific APT groups — only what the image shows.
2. The correct answer is typically a small subset (1-3 options). Over-selecting
   is penalised as much as omission.
3. Respond with a single JSON object on a single line:
   {"answer": ["A"], "reasoning": "1-sentence justification citing image evidence"}
4. The "answer" field MUST be a JSON array of capital letters from the option list.
"""


def load_questions(path: Path) -> list[dict]:
    if not path.exists():
        sys.exit(f"questions.json not found at {path}. See module docstring.")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        sys.exit(f"unexpected questions.json shape: {type(data).__name__}")
    return data


def index_images(root: Path) -> dict[str, Path]:
    """Map image filename stem → image file path."""
    if not root.exists():
        sys.exit(f"images root not found at {root}")
    index: dict[str, Path] = {}
    for f in root.rglob("*"):
        if f.is_file() and f.suffix.lower() in (".png", ".jpg", ".jpeg", ".webp"):
            index[f.stem] = f
            index[f.name] = f
    return index


def build_messages_openai(question: dict, image_path: Path) -> list[dict]:
    """Build the OpenAI vision message payload (images as base64)."""
    img_bytes = image_path.read_bytes()
    b64 = base64.b64encode(img_bytes).decode("utf-8")
    suffix = image_path.suffix.lower().lstrip(".")
    mime = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "webp": "image/webp"}.get(suffix, "image/png")
    options_block = "\n".join(question["options"])
    user_text = (
        f"# Question\n{question['question']}\n\n"
        f"# Options\n{options_block}\n\n"
        "Respond with the JSON object as instructed."
    )
    return [
        {
            "role": "user",
            "content": [
                {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}},
                {"type": "text", "text": user_text},
            ],
        }
    ]


def call_openai_vision(messages: list[dict], model: str = "gpt-4o-mini") -> str | None:
    """Call OpenAI vision API."""
    try:
        import openai  # noqa: PLC0415
        client = openai.OpenAI()
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": SYSTEM_PROMPT}] + messages,
            max_tokens=256,
            temperature=0,
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"  [WARN] OpenAI call failed: {e}", file=sys.stderr)
        return None


def parse_answer(raw: str | None) -> tuple[set[str], str]:
    """Robust JSON extraction of answer letters (same logic as malware eval)."""
    if not raw:
        return set(), ""
    text = raw.strip()
    if "```" in text:
        parts = text.split("```")
        for p in parts:
            p = p.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("{"):
                text = p
                break
    try:
        obj = json.loads(text)
        ans = obj.get("answer", [])
        if isinstance(ans, str):
            ans = [ans]
        letters = {str(a).strip().upper()[:1] for a in ans}
        return {l for l in letters if l in OPTION_LETTERS}, raw
    except json.JSONDecodeError:
        seen = set()
        for ch in raw.upper():
            if ch in OPTION_LETTERS:
                seen.add(ch)
            if len(seen) >= 4:
                break
        return seen, raw


def jaccard(predicted: set[str], correct: set[str]) -> float:
    if not predicted and not correct:
        return 1.0
    union = predicted | correct
    return len(predicted & correct) / len(union) if union else 0.0


def run(args) -> dict:
    questions = load_questions(Path(args.questions))
    images = index_images(Path(args.images_root))

    eligible = [q for q in questions if q.get("image") in images or (q.get("image") and q["image"].split("/")[-1] in images)]
    print(f"Loaded {len(questions)} questions; {len(eligible)} have matching images.")

    if args.seed is not None:
        random.seed(args.seed)
        random.shuffle(eligible)

    if args.limit and args.limit > 0:
        eligible = eligible[: args.limit]
        print(f"Limiting to {len(eligible)} questions.")

    results = []
    start = time.time()
    for i, q in enumerate(eligible, 1):
        img_key = q.get("image", "")
        img_path = images.get(img_key) or images.get(img_key.split("/")[-1])
        if img_path is None:
            continue

        messages = build_messages_openai(q, img_path)
        t0 = time.perf_counter()
        raw = call_openai_vision(messages, model=args.model)
        elapsed = time.perf_counter() - t0
        predicted, _ = parse_answer(raw)
        correct = set(q.get("correct_options", []))

        outcome = {
            "index": i,
            "question_id": q.get("id"),
            "attack": q.get("attack"),
            "predicted": sorted(predicted),
            "correct": sorted(correct),
            "exact_match": predicted == correct,
            "jaccard": round(jaccard(predicted, correct), 4),
            "llm_seconds": round(elapsed, 2),
        }
        if args.verbose:
            mark = "✅" if outcome["exact_match"] else ("≈" if outcome["jaccard"] > 0 else "❌")
            print(f"  {mark} [{i:>3}/{len(eligible)}] pred={outcome['predicted']} gt={outcome['correct']} J={outcome['jaccard']:.2f}")
        results.append(outcome)

    total = len(results)
    if total == 0:
        print("No results — check image paths.")
        return {}
    exact = sum(1 for r in results if r["exact_match"])
    avg_jac = sum(r["jaccard"] for r in results) / total

    summary = {
        "benchmark": "CyberSOCEval / Threat Intelligence Reasoning (subset)",
        "provider": args.provider,
        "model": args.model,
        "questions_evaluated": total,
        "exact_match_accuracy": round(exact / total, 4),
        "mean_jaccard_similarity": round(avg_jac, 4),
        "wall_seconds": round(time.time() - start, 1),
        "notes": [
            "Requires multimodal (vision) provider — NOT run in NVIDIA-NIM-only budget.",
            "Harness is complete; results pending a vision-capable API call.",
        ],
    }

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"summary": summary, "results": results}, indent=2))
        print(f"\nWrote {out}")

    print()
    print("=" * 60)
    print("  CyberSOCEval — Threat Intel Reasoning")
    print(f"  Questions evaluated: {total}")
    print(f"  Exact-match acc    : {summary['exact_match_accuracy']*100:.1f}%")
    print(f"  Mean Jaccard        : {summary['mean_jaccard_similarity']:.4f}")
    print()
    return summary


def main():
    ap = argparse.ArgumentParser(description="CyberSOCEval threat-intel reasoning eval")
    ap.add_argument("--questions", default="~/tmp/PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta/threat_intel/questions.json")
    ap.add_argument("--images-root", default="~/tmp/CyberSOCEval_data/data/threat-intel")
    ap.add_argument("--provider", default="openai-vision", help="Must be a vision-capable provider")
    ap.add_argument("--model", default="gpt-4o-mini")
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--output", default="docs/cybersoceval_threat_intel_results.json")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()
    args.questions = str(Path(args.questions).expanduser())
    args.images_root = str(Path(args.images_root).expanduser())
    run(args)


if __name__ == "__main__":
    main()
