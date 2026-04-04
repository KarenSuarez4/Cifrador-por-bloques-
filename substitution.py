"""Capa no lineal de sustitución del cifrador por bloques.

Arquitectura de la capa:
- aplica una S-Box afín sobre índices del alfabeto,
- incorpora mezcla de subclave por posición,
- define transformación directa e inversa para permitir descifrado exacto.
"""

from bit_utils import clave_posicion
from constants import ALFABETO, A_INV, A_S, B_S, TAM_ALFA


def s_box(idx: int) -> int:
    """Evalúa la S-Box base sobre un índice del alfabeto.

    Args:
        idx: Índice de entrada en el dominio [0, TAM_ALFA - 1].

    Returns:
        Índice transformado por la S-Box.
    """
    return (A_S * idx + B_S) % TAM_ALFA


def s_box_inv(idx: int) -> int:
    """Evalúa la inversa de la S-Box base.

    Args:
        idx: Índice transformado por la S-Box.

    Returns:
        Índice original previo a la S-Box.
    """
    return (A_INV * (idx - B_S)) % TAM_ALFA


def sustitucion(bloque: str, K_r: int) -> str:
    """Aplica sustitución símbolo a símbolo con clave de ronda.

    Args:
        bloque: Estado de entrada de la ronda.
        K_r: Subclave de ronda.

    Returns:
        Estado transformado tras sustitución.
    """
    resultado = ""
    for i in range(len(bloque)):
        idx = ALFABETO.index(bloque[i])
        idx_s = s_box(idx)
        k_i = clave_posicion(K_r, i)
        idx_f = (idx_s + k_i) % TAM_ALFA
        resultado += ALFABETO[idx_f]
    return resultado


def sustitucion_inversa(bloque: str, K_r: int) -> str:
    """Revierte la capa de sustitución para descifrado.

    Args:
        bloque: Estado de entrada en fase de descifrado.
        K_r: Subclave de la ronda correspondiente.

    Returns:
        Estado previo a la sustitución directa.
    """
    resultado = ""
    for i in range(len(bloque)):
        idx_f = ALFABETO.index(bloque[i])
        k_i = clave_posicion(K_r, i)
        idx_s = (idx_f - k_i) % TAM_ALFA
        idx = s_box_inv(idx_s)
        resultado += ALFABETO[idx]
    return resultado
