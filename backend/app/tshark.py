from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .config import settings


class TsharkError(RuntimeError):
    pass


def resolve_tshark() -> str | None:
    candidates = [
        settings.tshark_path,
        shutil.which("tshark"),
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]

    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.exists():
            return str(path)
        if candidate == "tshark":
            return candidate
    return None


def tshark_available() -> bool:
    return resolve_tshark() is not None


def tshark_version() -> str | None:
    tshark = resolve_tshark()
    if not tshark:
        return None
    try:
        result = subprocess.run(
            [tshark, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    first_line = result.stdout.splitlines()[0] if result.stdout else ""
    return first_line or None


def run_tshark(pcap_path: Path, args: list[str], timeout: int | None = None) -> str:
    tshark = resolve_tshark()
    if not tshark:
        raise TsharkError("tshark nao encontrado no PATH nem nos caminhos padrao do Wireshark")

    command = [tshark, "-r", str(pcap_path), *args]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout or settings.tshark_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TsharkError("Timeout ao executar tshark") from exc
    except OSError as exc:
        raise TsharkError(f"Falha ao executar tshark: {exc}") from exc

    if result.returncode not in (0, 1):
        stderr = result.stderr.strip() or "erro desconhecido"
        raise TsharkError(f"tshark retornou erro: {stderr}")
    return result.stdout


def parse_float(value: str | None) -> float | None:
    if value is None:
        return None
    cleaned = value.strip().replace(",", ".")
    match = re.search(r"-?\d+(?:\.\d+)?", cleaned)
    if not match:
        return None
    return float(match.group(0))


def parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    match = re.search(r"-?\d+", value.strip())
    if not match:
        return None
    return int(match.group(0))
