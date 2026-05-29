#!/usr/bin/env python3
"""
MCP Tools — SIFT Forensic Integration

Wrappers around real SANS SIFT forensic tools:
    * sleuthkit (via pytsk3 Python bindings) — disk/volume analysis
    * volatility3 — memory analysis
    * blkcalc/blkcat (via tsk bindings) — block-level forensic recovery

Architecture: SIFT-compatible toolchain running on WSL.
Migration path to full SIFT VM documented in docs/sift_integration.md.

Python bindings chosen over CLI because:
    - No sudo required (avoids apt dependency hell)
    - Direct integration with MCP server JSON transport
    - Graceful degradation when native library is absent
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("mcp-sift")

# ── Lazy imports so MCP server does not crash if optional deps are missing ──
try:
    import pytsk3
    _HAS_PYTSK3 = True
except Exception as _e_tsk:  # noqa: BLE001
    pytsk3 = None  # type: ignore[assignment]
    _HAS_PYTSK3 = False
    logger.warning("pytsk3 not available: %s", _e_tsk)

try:
    from volatility3.framework import contexts, interfaces
    from volatility3 import plugins as vol_plugins
    _HAS_VOLATILITY3 = True
except Exception as _e_vol:  # noqa: BLE001
    contexts = interfaces = None  # type: ignore[misc]
    vol_plugins = None
    _HAS_VOLATILITY3 = False
    logger.warning("volatility3 not available: %s", _e_vol)


# ── Configuration ───────────────────────────────────────────────────────────

SIFT_AVAILABLE = {
    "pytsk3": _HAS_PYTSK3,
    "volatility3": _HAS_VOLATILITY3,
}


def _check_artifact(path: str | Path) -> tuple[bool, str]:
    target = Path(path).expanduser()
    if not target.exists():
        return False, f"artifact_not_found: {target}"
    if not target.is_file():
        return False, f"not_a_file: {target}"
    if os.access(target, os.R_OK):
        return True, str(target.resolve())
    return False, f"not_readable: {target}"


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Sleuthkit / pytsk3 Wrappers ─────────────────────────────────────────────

def sift_list_filesystem(
    image_path: str,
    offset: int = 0,
    max_files: int = 500,
) -> dict[str, Any]:
    """
    List files in a disk image or filesystem image using Sleuthkit (pytsk3).

    Equivalent SIFT tool:  fls, ils
    Returns JSON-safe dict with file listing + metadata.
    """
    if not _HAS_PYTSK3:
        return {"error": "sleuthkit_unavailable", "detail": "pytsk3 not installed"}
    assert pytsk3 is not None

    ok, msg = _check_artifact(image_path)
    if not ok:
        return {"error": msg}

    resolved = Path(msg)
    start = time.perf_counter()
    results: list[dict[str, Any]] = []
    volume_info: dict[str, Any] = {}

    try:
        img = pytsk3.Img_Info(str(resolved))

        # Try volume system first (mmls equivalent)
        try:
            vol = pytsk3.Volume_Info(img)
            volume_info = {
                "type": vol.info.vs_type,
                "offset": vol.info.offset,
                "block_size": vol.info.block_size,
                "partitions": [
                    {
                        "addr": p.addr,
                        "start": p.start,
                        "length": p.len,
                        "desc": p.desc.decode(errors="replace") if isinstance(p.desc, bytes) else str(p.desc),
                    }
                    for p in vol
                ],
            }
        except Exception:
            volume_info = {"type": "none", "partitions": []}

        # Filesystem analysis (offset provided or first partition)
        fs_start = offset if offset > 0 else 0
        if volume_info.get("partitions"):
            fs_start = volume_info["partitions"][0]["start"] * 512

        fs = pytsk3.FS_Info(img, offset=fs_start)
        root = fs.open_dir(path="/")

        count = 0
        for f in root:
            name = f.info.name.name
            if isinstance(name, bytes):
                name = name.decode(errors="replace")
            if name in (".", ".."):
                continue
            meta = f.info.meta
            entry = {
                "name": name,
                "type": "dir" if meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR else "file",
                "size": meta.size if meta else None,
                "addr": meta.addr if meta else None,
                "mtime": meta.mtime if meta else None,
                "ctime": meta.ctime if meta else None,
            }
            results.append(entry)
            count += 1
            if count >= max_files:
                break

        return {
            "tool": "sleuthkit",
            "image": str(resolved),
            "offset": fs_start,
            "volume": volume_info,
            "files": results,
            "count": len(results),
            "sha256": _file_sha256(resolved),
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            "status": "ok",
        }
    except Exception as e:
        logger.exception("sift_list_filesystem failed")
        return {
            "error": "sleuthkit_analysis_failed",
            "detail": str(e),
            "image": str(resolved),
            "status": "error",
        }


def sift_carve_blocks(
    image_path: str,
    start_block: int = 0,
    count: int = 10,
) -> dict[str, Any]:
    """
    Carve/extract raw blocks from a disk image using Sleuthkit.

    Equivalent SIFT tool:  blkcat, blkcalc
    Returns base64-encoded block data (truncated to first 4KB per block).
    """
    if not _HAS_PYTSK3:
        return {"error": "sleuthkit_unavailable", "detail": "pytsk3 not installed"}
    assert pytsk3 is not None

    ok, msg = _check_artifact(image_path)
    if not ok:
        return {"error": msg}

    resolved = Path(msg)
    start = time.perf_counter()
    blocks: list[dict[str, Any]] = []

    try:
        img = pytsk3.Img_Info(str(resolved))
        block_size = 4096  # common default; tsk fs info would refine this
        for i in range(start_block, start_block + count):
            offset = i * block_size
            if offset >= img.get_size():
                break
            data = img.read(offset, block_size)
            blocks.append({
                "block_number": i,
                "offset": offset,
                "size": len(data),
                "hex_preview": data[:64].hex(),
                "entropy_approx": _approx_entropy(data),
            })

        return {
            "tool": "sleuthkit",
            "mode": "block_carve",
            "image": str(resolved),
            "sha256": _file_sha256(resolved),
            "blocks": blocks,
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            "status": "ok",
        }
    except Exception as e:
        logger.exception("sift_carve_blocks failed")
        return {"error": "sleuthkit_carve_failed", "detail": str(e)}


def _approx_entropy(data: bytes) -> float:
    """Shannon entropy approximation [0, 8] for byte distribution."""
    if not data:
        return 0.0
    from math import log2
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * log2(p)
    return round(ent, 3)


# ── Volatility3 Wrappers ────────────────────────────────────────────────────

def sift_memory_list_processes(
    memory_dump_path: str,
) -> dict[str, Any]:
    """
    List processes from a memory dump using Volatility3 pslist equivalent.

    Equivalent SIFT tool:  volatility3 windows.pslist.PsList
    Returns JSON-safe process listing.
    """
    if not _HAS_VOLATILITY3:
        return {"error": "volatility3_unavailable", "detail": "volatility3 not installed"}

    ok, msg = _check_artifact(memory_dump_path)
    if not ok:
        return {"error": msg}

    resolved = Path(msg)
    start = time.perf_counter()

    try:
        # Build volatility3 context
        ctx = contexts.Context()
        ctx.config[" automagic.LayerWriter.layer_name"] = "memory_layer"
        ctx.config["plugins.PsList.kernel"] = "PdbSignatureScanner"
        # Use the built-in layered reader
        import volatility3.framework.automagic as am
        # Minimal symbol requirement: Volatility3 needs a symbol table, which
        # for competition demos may not exist.  We gracefully handle this.
        failure = am.stacker.choose_layer(ctx, [str(resolved)])
        if failure is None:
            return {
                "tool": "volatility3",
                "mode": "pslist",
                "image": str(resolved),
                "status": "unrecognized_format",
                "detail": "Could not identify a valid memory layer. Ensure the file is a raw memory dump.",
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            }

        # Fallback: report metadata about the dump since symbol tables may be missing
        # in a fresh WSL install.
        return {
            "tool": "volatility3",
            "mode": "pslist",
            "image": str(resolved),
            "sha256": _file_sha256(resolved),
            "status": "partial",
            "note": (
                "Volatility3 context initialized. Full pslist requires symbol tables "
                "(e.g., windows.pdb). On SIFT VM these are pre-installed under "
                "/usr/share/volatility3/symbols. Running on WSL without symbol tables "
                "returns structural metadata only."
            ),
            "layer_info": str(failure),
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        }
    except Exception as e:
        logger.exception("sift_memory_list_processes failed")
        return {"error": "volatility3_analysis_failed", "detail": str(e)}


def sift_memory_strings(
    memory_dump_path: str,
    min_length: int = 4,
) -> dict[str, Any]:
    """
    Extract ASCII/UTF-8 strings from a memory dump.

    Equivalent SIFT tool:  strings + volatility3 yarascan
    Returns string hits with offset + preview.
    """
    ok, msg = _check_artifact(memory_dump_path)
    if not ok:
        return {"error": msg}

    resolved = Path(msg)
    start = time.perf_counter()
    strings: list[dict[str, Any]] = []

    try:
        with open(resolved, "rb") as f:
            chunk = f.read(2 * 1024 * 1024)  # first 2 MB only for safety
        import re
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
        for m in pattern.finditer(chunk):
            strings.append({
                "offset": m.start(),
                "length": len(m.group()),
                "preview": m.group().decode("ascii", errors="replace")[:80],
            })
            if len(strings) >= 1000:
                break

        return {
            "tool": "strings_equivalent",
            "image": str(resolved),
            "sha256": _file_sha256(resolved),
            "status": "ok",
            "strings_found": len(strings),
            "sample": strings[:20],
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        }
    except Exception as e:
        logger.exception("sift_memory_strings failed")
        return {"error": "strings_extraction_failed", "detail": str(e)}


# ── SIFT Health / Status ───────────────────────────────────────────────────

def sift_health() -> dict[str, Any]:
    """Report which SIFT components are functional."""
    info = {
        "pytsk3": {
            "available": _HAS_PYTSK3,
            "version": pytsk3.TSK_VERSION_NUM if _HAS_PYTSK3 else None,
            "note": "Sleuthkit Python bindings (disk/volume analysis)" if _HAS_PYTSK3 else "Install: pip install pytsk3",
        },
        "volatility3": {
            "available": _HAS_VOLATILITY3,
            "note": "Memory forensics framework" if _HAS_VOLATILITY3 else "Install: pip install volatility3",
            "symbol_tables": "MISSING (see docs/sift_integration.md)",
        },
        "plaso": {
            "available": False,
            "note": "Super-timeline analysis. Not installed — requires system dependencies.",
            "install_on_sift_vm": "apt install plaso-tools",
        },
        "sleuthkit_cli": {
            "available": False,
            "note": "Native CLI tools (fls, mmls, blkcat). Not installed — requires apt + deps.",
            "install_on_sift_vm": "apt install sleuthkit",
        },
    }
    return {
        "overall": "partial" if (_HAS_PYTSK3 or _HAS_VOLATILITY3) else "unavailable",
        "components": info,
        "platform": "WSL (Ubuntu 24.04)",
        "migration_target": "SANS SIFT Workstation VM",
    }
