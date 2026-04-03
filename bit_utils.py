"""Utilidades de bits y extraccion de clave por posicion."""

from constants import MASK64, TAM_ALFA


def rotl64(x: int, n: int) -> int:
    """Rotacion izquierda de x en 64 bits por n posiciones."""
    n = n % 64
    if n == 0:
        return x & MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64


def clave_posicion(K_r: int, i: int) -> int:
    """Extrae k_i para la posicion i en el rango [0, 61]."""
    Kr_rot = rotl64(K_r, i * 3)
    return Kr_rot % TAM_ALFA
