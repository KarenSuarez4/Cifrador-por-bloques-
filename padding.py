"""Funciones de padding del bloque fijo."""

from constants import CHAR_PAD, LARGO_BLOQUE


def aplicar_padding(M: str) -> str:
    """Completa M hasta 20 caracteres usando CHAR_PAD."""
    if len(M) > LARGO_BLOQUE:
        raise ValueError(f"Mensaje demasiado largo: {len(M)} > {LARGO_BLOQUE}.")
    return M + CHAR_PAD * (LARGO_BLOQUE - len(M))


def quitar_padding(bloque: str, M_len: int) -> str:
    """Recupera los primeros M_len caracteres del bloque."""
    return bloque[:M_len]
