"""Generacion de clave maestra y expansion por rondas."""

from bit_utils import rotl64
from constants import MASK64


def generar_clave(M: str) -> int:
    """Genera la clave maestra K de 64 bits desde el mensaje M."""
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
    """Deriva la subclave K_r para la ronda indicada."""
    PRIMA_E = 0xB7E151628AED2A6B

    K_r = rotl64(K, ronda * 3)
    K_r = (K_r ^ ((ronda * PRIMA_E) & MASK64)) & MASK64
    return K_r
