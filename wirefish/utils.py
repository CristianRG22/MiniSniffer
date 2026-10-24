"""Funciones auxiliares compartidas por la aplicación."""

from __future__ import annotations

import logging


def configure_logging(level: int = logging.INFO) -> None:
    """Configura logging básico sin duplicar handlers existentes."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def decode_payload(payload: bytes, max_chars: int = 8000) -> str:
    """Decodifica bytes para mostrarlos con seguridad en una vista de texto."""
    if not payload:
        return "(sin carga útil)"
    decoded = payload.decode("utf-8", errors="replace")
    control_chars = sum(
        1 for character in decoded if ord(character) < 32 and character not in "\r\n\t"
    )
    if decoded and control_chars / len(decoded) > 0.1:
        decoded = payload.hex(" ")
    if len(decoded) > max_chars:
        decoded = f"{decoded[:max_chars]}\n... (contenido truncado)"
    return decoded