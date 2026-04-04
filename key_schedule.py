"""Subsistema de claves: clave maestra y subclaves por ronda.

Este módulo define la política de derivación de claves del cifrador:
- generación determinista de la clave maestra de 64 bits desde el mensaje,
- expansión de una subclave distinta para cada ronda.
"""

from bit_utils import rotl64
from constants import MASK64


def generar_clave(M: str) -> int:
    """Genera la clave maestra de 64 bits a partir del mensaje.

    El proceso combina rotaciones, desplazamientos y XOR por carácter para
    introducir difusión sobre el estado de clave.

    Args:
        M: Mensaje de entrada (sin padding).

    Returns:
        Clave maestra de 64 bits distinta de cero.
    """
    K = 0x9E3779B97F4A7C15

    for i in range(len(M)):
        c_val = ord(M[i])
        rot = (i * 7 + 3) % 64
        desp = (i * 11) % 57

        K = rotl64(K, rot)
        K = (K ^ (c_val << desp)) & MASK64
        K = ((K | (c_val << 8)) ^ (K >> 5)) & MASK64

    K = (K ^ 0xB7E151628AED2A6B) & MASK64
    return K if K != 0 else 0x9E3779B97F4A7C15


def expandir_subclave(K: int, ronda: int) -> int:
    """Deriva la subclave correspondiente a una ronda específica.

    Args:
        K: Clave maestra de 64 bits.
        ronda: Índice de ronda (base 1).

    Returns:
        Subclave de 64 bits para la ronda solicitada.
    """
    PRIMA_E = 0xB7E151628AED2A6B

    K_r = rotl64(K, ronda * 3)
    K_r = (K_r ^ ((ronda * PRIMA_E) & MASK64)) & MASK64
    return K_r
