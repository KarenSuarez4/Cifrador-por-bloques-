"""Gestión de longitud de bloque para la interfaz cifrado/descifrado.

Este módulo adapta mensajes de longitud variable al tamaño fijo requerido
por el cifrado por bloques y recupera la longitud original al descifrar.
"""

from constants import CHAR_PAD, LARGO_BLOQUE


def aplicar_padding(M: str) -> str:
    """Completa un mensaje hasta `LARGO_BLOQUE` usando `CHAR_PAD`.

    Args:
        M: Mensaje original.

    Returns:
        Bloque de longitud fija.

    Raises:
        ValueError: Si el mensaje supera el tamaño de bloque permitido.
    """
    if len(M) > LARGO_BLOQUE:
        raise ValueError(f"Mensaje demasiado largo: {len(M)} > {LARGO_BLOQUE}.")
    return M + CHAR_PAD * (LARGO_BLOQUE - len(M))


def quitar_padding(bloque: str, M_len: int) -> str:
    """Recupera el mensaje original truncando al largo conocido.

    Args:
        bloque: Texto descifrado de longitud fija.
        M_len: Longitud real del mensaje previo al padding.

    Returns:
        Mensaje original sin relleno.
    """
    return bloque[:M_len]
