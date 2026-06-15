"""Direct tests for the heterogeneity mandate (kinship-lock detection).

This guards the core thesis: a same-family propagator/auditor pair must be flagged
(ΔA=0, kinship_lock_risk=HIGH, mandate NOT met), and a cross-family pair must pass
(ΔA=1, LOW, mandate met). Family detection must also resolve the real model names
used by the default providers, not fall back to "unknown".
"""

import pytest

from triage_orchestrator import _detect_family, _check_heterogeneity


@pytest.mark.parametrize("model,family", [
    ("openai/gpt-oss-120b:free", "gpt-oss"),
    ("nvidia/nemotron-3-ultra-550b-a55b:free", "nemotron"),
    ("mistralai/mistral-nemotron", "nemotron"),          # nemotron wins over mistral
    ("nvidia/llama-3.3-nemotron-super-49b-v1", "nemotron"),  # nemotron wins over llama
    ("meta/llama-3.3-70b-instruct", "llama"),
    ("deepseek/deepseek-chat-v3-0324:free", "deepseek"),
    ("qwen/qwen3-32b:free", "qwen"),
    ("minimax-m3", "minimax"),
    ("z-ai/glm-4.5-air:free", "glm"),
    ("something-unrecognized-v9", "unknown"),
])
def test_detect_family(model, family):
    assert _detect_family(model) == family


def test_cross_family_pair_meets_mandate():
    """Default pairing: gpt-oss propagator vs nemotron auditor -> heterogeneous."""
    h = _check_heterogeneity("openai/gpt-oss-120b:free", "nvidia/nemotron-3-ultra-550b-a55b:free")
    assert h["architectural_distance"] == 1.0
    assert h["kinship_lock_risk"] == "LOW"
    assert h["heterogeneity_mandate_met"] is True


def test_same_family_pair_flags_kinship_lock():
    """nvidia-nim propagator + nemotron auditor are the SAME family -> kinship lock."""
    h = _check_heterogeneity("mistralai/mistral-nemotron", "nvidia/nemotron-3-ultra")
    assert h["architectural_distance"] == 0.0
    assert h["kinship_lock_risk"] == "HIGH"
    assert h["heterogeneity_mandate_met"] is False


@pytest.mark.parametrize("family_model", [
    "deepseek/deepseek-chat-v3-0324",
    "meta/llama-3.3-70b-instruct",
    "qwen/qwen3-32b",
    "openai/gpt-oss-120b",
    "nvidia/nemotron-3-ultra",
])
def test_any_same_family_self_pair_is_kinship_lock(family_model):
    """The fix: ANY same-family pair is flagged, not only nemotron-vs-nemotron."""
    h = _check_heterogeneity(family_model, family_model)
    assert h["kinship_lock_risk"] == "HIGH"
    assert h["heterogeneity_mandate_met"] is False


def test_unknown_vs_unknown_is_not_falsely_heterogeneous():
    """Two unidentifiable models must not be asserted heterogeneous (can't prove ΔA)."""
    h = _check_heterogeneity("mystery-a", "mystery-b")
    # both -> "unknown"; same_family guard excludes "unknown", so mandate stays unmet
    assert h["heterogeneity_mandate_met"] is False
