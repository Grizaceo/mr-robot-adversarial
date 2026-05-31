#!/usr/bin/env python3
"""
SIFT Forensic Tools — CLI Wrapper
Migración desde pytsk3/volatility3 Python bindings hacia
comandos nativos SIFT Workstation (fls, mmls, blkcat, strings, vol.py).

Detecta automáticamente el entorno:
  - WSL / local   → usa Python bindings (modo prototype)
  - SIFT VM reachable → usa CLI nativo (modo production)

Uso:
  from mcp_tools_sift import sift_list_filesystem, sift_carve_blocks, ...
"""

import dataclasses
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional


# ── Detección de entorno ──────────────────────────────────────────────
_SIFT_VM_HOST = os.getenv("SIFT_VM_HOST", "")  # e.g. "192.168.56.101"
_SIFT_VM_USER = os.getenv("SIFT_VM_USER", "sift")
_SIFT_SSH_KEY = os.getenv("SIFT_SSH_KEY", "")  # ruta a .pem

_WSL_ROOT = Path("/mnt/c")
_HOME = Path.home()


def _is_sift_vm() -> bool:
    """True si detectamos host SIFT VM y SSH accesible."""
    if not _SIFT_VM_HOST:
        return False
    if not _SIFT_SSH_KEY:
        return False
    # Quick liveness check (sin stdin interactivo)
    try:
        r = subprocess.run(
            ["ssh", "-i", _SIFT_SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "BatchMode=yes", "-o", "ConnectTimeout=3",
             f"{_SIFT_VM_USER}@{_SIFT_VM_HOST}", "echo ok"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0 and "ok" in r.stdout
    except Exception:
        return False


_ENV = "SIFT_VM" if _is_sift_vm() else "WSL_LOCAL"
# Debug opcional
# print(f"[sift_tools] entorno detectado: {_ENV}")


# ── Helpers de ejecución remota/local ─────────────────────────────────
def _run_ssh(cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """Ejecuta comando en la VM SIFT vía SSH."""
    ssh_base = [
        "ssh", "-i", _SIFT_SSH_KEY,
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        f"{_SIFT_VM_USER}@{_SIFT_VM_HOST}",
    ]
    full_cmd = ssh_base + cmd
    return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)


def _run_local(cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """Ejecuta comando local (WSL prototype)."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ── Dataclasses de salida ─────────────────────────────────────────────
@dataclasses.dataclass
class FileEntry:
    name: str
    type: str  # "file" | "dir"
    size: int
    addr: int
    sha256: Optional[str] = None


@dataclasses.dataclass
class CampaignResult:
    campaign_detected: bool
    campaign_id: Optional[str]
    severity: str
    tool_name: Optional[str]
    ioc_pattern: Optional[str]
    event_count: int
    window_hours: int
    db_path: str


# ── SIFT Tools ────────────────────────────────────────────────────────
def sift_list_filesystem(image_path: str, offset: int = 0) -> dict:
    """
    Lista archivos de una imagen de disco.
    Equivalente SIFT: fls -r -o <offset> <image>
    """
    if _ENV == "SIFT_VM":
        cmd = ["fls", "-r", "-o", str(offset), image_path]
        r = _run_ssh(cmd)
        # Parsear salida tipo fls (formato TSK)
        files = _parse_fls_output(r.stdout)
        return {"tool": "fls", "image": image_path, "offset": offset,
                "files": [dataclasses.asdict(f) for f in files],
                "status": "ok" if r.returncode == 0 else "error",
                "stderr": r.stderr[:500] if r.stderr else ""}
    else:
        # WSL prototype: pytsk3
        try:
            import pytsk3
            img = pytsk3.Img_Info(image_path)
            vol = pytsk3.Volume_Info(img)
            fs = pytsk3.FS_Info(vol.get_volume(offset) if offset else vol.get_volume(0))
            files = []
            for f in fs.open_dir("/"):
                files.append(FileEntry(
                    name=f.info.name.name.decode() if f.info.name else "?",
                    type="dir" if f.info.meta else "file",
                    size=f.info.meta.size if f.info.meta else 0,
                    addr=f.addr,
                ))
            return {"tool": "pytsk3", "image": image_path, "offset": offset,
                    "files": [dataclasses.asdict(f) for f in files[:200]],
                    "status": "ok"}
        except ImportError:
            return {"error": "pytsk3_unavailable"}


def _parse_fls_output(stdout: str) -> List[FileEntry]:
    """Parse minimal de salida `fls -r`."""
    files = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # fls usa formato: r/r * 2048:    nombre (symlink target)
        parts = line.split()
        if len(parts) >= 2:
            ftype = "dir" if parts[0].startswith("d") else "file"
            name = parts[-1]
            files.append(FileEntry(name=name, type=ftype, size=0, addr=0))
    return files


def sift_carve_blocks(
    image_path: str, start_block: int = 0, count: int = 10
) -> dict:
    """
    Extrae bloques raw de una imagen.
    Equivalente SIFT: blkcat -o <offset> <image> <block> [block ...]
    """
    block_size = 4096
    blocks = []
    if _ENV == "SIFT_VM":
        # Obtener offset del filesystem primero (simplificado a offset=0)
        cmd = ["blkcat", "-o", "0", image_path, str(start_block)]
        if count > 1:
            cmd += [str(start_block + i) for i in range(count)]
        r = _run_ssh(cmd, timeout=30)
        if r.returncode == 0:
            raw = r.stdout
            for i in range(min(count, len(raw) // block_size + 1)):
                offset = (start_block + i) * block_size
                chunk = raw[i * block_size : (i + 1) * block_size]
                entropy = _approx_entropy(chunk)
                blocks.append({
                    "block_number": start_block + i,
                    "offset": offset,
                    "size": block_size,
                    "entropy_approx": round(entropy, 3),
                })
        return {"tool": "blkcat", "image": image_path,
                "blocks": blocks, "status": "ok" if r.returncode == 0 else "error"}
    else:
        # WSL prototype
        try:
            with open(image_path, "rb") as f:
                f.seek(start_block * block_size)
                for i in range(count):
                    chunk = f.read(block_size)
                    if not chunk:
                        break
                    offset = (start_block + i) * block_size
                    blocks.append({
                        "block_number": start_block + i,
                        "offset": offset,
                        "size": len(chunk),
                        "entropy_approx": _approx_entropy(chunk),
                    })
            return {"tool": "python_carve", "image": image_path,
                    "blocks": blocks, "status": "ok"}
        except Exception as e:
            return {"error": str(e)}


def _approx_entropy(data: bytes) -> float:
    """Entropía Shannon aproximada (0–8)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * (p ** -1 and __import__("math").log2(p) or 0)
    return ent


def sift_memory_list_processes(memory_dump_path: str) -> dict:
    """
    Lista procesos de un dump de memoria.
    Equivalente SIFT: vol.py -f <dump> windows.pslist.PsList
    """
    if _ENV == "SIFT_VM":
        cmd = ["vol.py", "-f", memory_dump_path, "windows.pslist.PsList"]
        r = _run_ssh(cmd, timeout=120)
        # Parseo mínimo: líneas tipo "Name     PID    ..."
        processes = []
        for line in r.stdout.splitlines()[2:]:  # skip header
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                processes.append({"name": parts[0], "pid": int(parts[1])})
        return {"tool": "volatility3", "dump": memory_dump_path,
                "processes": processes, "status": "ok" if r.returncode == 0 else "error",
                "stderr": r.stderr[:500] if r.stderr else ""}
    else:
        # WSL prototype: volatility3 framework
        try:
            import volatility3  # noqa
            # No cargamos simbolios; solo reportamos disponibilidad
            return {"tool": "volatility3_framework",
                    "dump": memory_dump_path,
                    "status": "ok",
                    "note": "Requiere symbol tables para parsear estructuras."}
        except ImportError:
            return {"error": "volatility3_unavailable"}


def sift_memory_strings(
    memory_dump_path: str, min_length: int = 4
) -> dict:
    """
    Extrae strings ASCII de un dump de memoria.
    Equivalente SIFT: strings -n <min_length> <dump>
    """
    if _ENV == "SIFT_VM":
        cmd = ["strings", "-n", str(min_length), memory_dump_path]
        r = _run_ssh(cmd, timeout=60)
        strings = [s.strip() for s in r.stdout.splitlines() if len(s.strip()) >= min_length]
        return {"tool": "strings", "dump": memory_dump_path,
                "strings_found": len(strings),
                "sample": strings[:20],
                "status": "ok" if r.returncode == 0 else "error"}
    else:
        # WSL prototype: Python puro
        try:
            strings = []
            current = b""
            with open(memory_dump_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    for b in chunk:
                        if 32 <= b <= 126:
                            current += bytes([b])
                        else:
                            if len(current) >= min_length:
                                strings.append(current.decode("ascii", errors="ignore"))
                            current = b""
            return {"tool": "python_strings", "dump": memory_dump_path,
                    "strings_found": len(strings),
                    "sample": strings[:20],
                    "status": "ok"}
        except Exception as e:
            return {"error": str(e)}


def sift_health() -> dict:
    """Reporta disponibilidad de componentes SIFT."""
    if _ENV == "SIFT_VM":
        checks = {
            "fls": shutil.which("fls") is not None,
            "mmls": shutil.which("mmls") is not None,
            "blkcat": shutil.which("blkcat") is not None,
            "strings": shutil.which("strings") is not None,
            "vol.py": shutil.which("vol.py") is not None,
            "plaso": shutil.which("log2timeline.py") is not None,
        }
    else:
        checks = {
            "pytsk3": shutil.which("python") is not None,  # pip check real abajo
            "volatility3": shutil.which("python") is not None,
        }
        try:
            import pytsk3
            checks["pytsk3"] = True
            checks["pytsk3_version"] = pytsk3.TSK_VERSION_NUM
        except ImportError:
            checks["pytsk3"] = False
        try:
            import volatility3  # noqa
            checks["volatility3"] = True
        except ImportError:
            checks["volatility3"] = False

    return {
        "overall": "full" if all(v is True or isinstance(v, int) for v in checks.values()) else "partial",
        "environment": _ENV,
        "components": checks,
        "sift_vm_host": _SIFT_VM_HOST or "not set",
    }


def sift_plaso_timeline(image_path: str, output_dir: str = "/tmp/sift_timeline") -> dict:
    """
    Genera super-timeline con plaso.
    Equivalente SIFT: log2timeline.py <output> <image>
    Solo disponible en VM SIFT completa.
    """
    if _ENV != "SIFT_VM":
        return {"error": "plaso_requires_vm",
                "note": "log2timeline.py necesita sleuthkit + plaso-tools en VM SIFT completa"}
    os.makedirs(output_dir, exist_ok=True)
    cmd = ["log2timeline.py", f"{output_dir}/timeline.plaso", image_path]
    r = _run_ssh(cmd, timeout=300)
    return {"tool": "plaso", "image": image_path,
            "output": f"{output_dir}/timeline.plaso",
            "status": "ok" if r.returncode == 0 else "error",
            "stderr": r.stderr[:500] if r.stderr else ""}
