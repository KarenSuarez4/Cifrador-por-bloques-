"""Funciones de padding del bloque fijo."""

from constants import ALFABETO, CHAR_PAD, LARGO_BLOQUE


def aplicar_padding(M: str) -> str:
    """Codifica la longitud y completa el bloque hasta 20 caracteres."""
    max_len = LARGO_BLOQUE - 1
    if len(M) > max_len:
        raise ValueError(f"Mensaje demasiado largo: {len(M)} > {max_len}.")
    len_tag = ALFABETO[len(M)]
    return len_tag + M + CHAR_PAD * (LARGO_BLOQUE - 1 - len(M))


def quitar_padding(bloque: str) -> str:
    """Recupera el mensaje original a partir del bloque autocontenible."""
    M_len = ALFABETO.index(bloque[0])
    return bloque[1 : 1 + M_len]
